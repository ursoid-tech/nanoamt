#define _POSIX_C_SOURCE 200809L
#include "nanoamt/native.h"
#include "nanoamt/openssl.h"
#include "nanoamt/relay_posix.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t stopping;
static void stop(int signal_number) {
  (void)signal_number;
  stopping = 1;
}
static int64_t clock_ms(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return -1;
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void usage(FILE *out) {
  fputs("usage: nanoamt-relay --interface NAME [--bind IP] [--port PORT]\n"
        "                     [--mtu BYTES] [--clients COUNT]\n"
        "                     [--groups COUNT] [--sources COUNT]\n"
        "                     [--input-queue COUNT] [--input-bytes BYTES]\n"
        "                     [--control-queue COUNT] [--send-budget COUNT]\n"
        "                     [--control-rate COUNT] [--source-rate COUNT]\n"
        "Linux classic AMT relay; needs CAP_NET_RAW for native multicast capture.\n",
        out);
}
static unsigned number(const char *text, unsigned limit) {
  char *end;
  errno = 0;
  unsigned long n = strtoul(text, &end, 10);
  if (errno || !*text || *end || !n || n > limit) {
    fprintf(stderr, "invalid numeric option: %s\n", text);
    exit(2);
  }
  return (unsigned)n;
}
static int prune(nanoamt_relay_posix *relay, nanoamt_native *native, int64_t now) {
  nanoamt_memberships *snapshot = NULL;
  int rc = nanoamt_relay_snapshot(nanoamt_relay_posix_core(relay), now, &snapshot);
  if (!rc)
    rc = nanoamt_native_reconcile(native, snapshot);
  nanoamt_memberships_free(snapshot);
  return rc;
}
int main(int argc, char **argv) {
  nanoamt_relay_posix_config relay_config = {0};
  nanoamt_native_config native_config = {0};
  relay_config.listen.port = NANOAMT_PORT;
  relay_config.relay.random_bytes = nanoamt_openssl_random;
  relay_config.relay.response_mac = nanoamt_openssl_response_mac;
  const char *interface = NULL;
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--help")) {
      usage(stdout);
      return 0;
    }
    if (i + 1 >= argc) {
      usage(stderr);
      return 2;
    }
    const char *option = argv[i++], *value = argv[i];
    if (!strcmp(option, "--interface"))
      interface = value;
    else if (!strcmp(option, "--bind")) {
      if (inet_pton(AF_INET, value, relay_config.listen.ip) == 1)
        relay_config.listen.ip_version = 4;
      else if (inet_pton(AF_INET6, value, relay_config.listen.ip) == 1)
        relay_config.listen.ip_version = 6;
      else {
        fprintf(stderr, "invalid bind address: %s\n", value);
        return 2;
      }
    } else if (!strcmp(option, "--port"))
      relay_config.listen.port = (uint16_t)number(value, 65535);
    else if (!strcmp(option, "--mtu"))
      relay_config.relay.path_mtu = number(value, 65535);
    else if (!strcmp(option, "--clients"))
      relay_config.relay.max_clients = number(value, 1024);
    else if (!strcmp(option, "--groups")) {
      native_config.max_groups = number(value, 4096);
      relay_config.relay.aggregate.max_groups = native_config.max_groups;
    } else if (!strcmp(option, "--sources")) {
      native_config.max_sources = number(value, 65536);
      relay_config.relay.aggregate.max_sources = native_config.max_sources;
    } else if (!strcmp(option, "--input-queue"))
      relay_config.input_capacity = number(value, 1024);
    else if (!strcmp(option, "--input-bytes"))
      relay_config.input_bytes = number(value, UINT_MAX);
    else if (!strcmp(option, "--control-queue"))
      relay_config.control_capacity = number(value, 1024);
    else if (!strcmp(option, "--send-budget"))
      relay_config.send_budget = number(value, 4096);
    else if (!strcmp(option, "--control-rate"))
      relay_config.control_rate = number(value, UINT_MAX);
    else if (!strcmp(option, "--source-rate"))
      relay_config.source_rate = number(value, UINT_MAX);
    else {
      usage(stderr);
      return 2;
    }
  }
  if (!interface || !(native_config.interface_index = if_nametoindex(interface))) {
    fputs("a valid --interface is required\n", stderr);
    return 2;
  }
  nanoamt_native *native = nanoamt_native_open(&native_config);
  if (!native) {
    perror("native multicast provider");
    return 1;
  }
  relay_config.relay.authorize = nanoamt_native_authorize;
  relay_config.relay.authorize_context = native;
  relay_config.mtu_feedback = nanoamt_native_mtu_feedback;
  relay_config.feedback_context = native;
  int64_t now = clock_ms();
  nanoamt_relay_posix *relay = nanoamt_relay_posix_open(&relay_config, now);
  if (!relay) {
    perror("relay listener");
    nanoamt_native_close(native);
    return 1;
  }
  struct sigaction action = {0};
  action.sa_handler = stop;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
    perror("signal handler");
    nanoamt_relay_posix_close(relay);
    nanoamt_native_close(native);
    return 1;
  }
  fprintf(stderr, "AMT relay listening on UDP %u; upstream interface %s\n", relay_config.listen.port, interface);
  int failed = 0;
  int previous_prune_error = 0;
  int64_t prune_logged_at = now;
  while (!stopping) {
    now = clock_ms();
    if (now < 0) {
      failed = 1;
      break;
    }
    int rc = nanoamt_relay_posix_send(relay, now);
    if (rc < 0) {
      fprintf(stderr, "relay service error %d\n", rc);
      failed = 1;
      break;
    }
    /* Prune stale/withdrawn upstream subscriptions after the core advances.
     * Failed native additions preserve old joins; core filtering still gates
     * reception while the controller retries reconciliation. */
    rc = prune(relay, native, now);
    if (rc && (rc != previous_prune_error || now - prune_logged_at >= 1000)) {
      fprintf(stderr, "native reconciliation error %d (%s)\n", rc, strerror(errno));
      prune_logged_at = now;
    }
    previous_prune_error = rc;
    struct pollfd fds[2] = {{nanoamt_relay_posix_fd(relay), POLLIN, 0}, {nanoamt_native_fd(native), POLLIN, 0}};
    if (nanoamt_relay_posix_wants_write(relay))
      fds[0].events |= POLLOUT;
    int64_t next = nanoamt_relay_posix_next_timeout(relay), delay = next > now ? next - now : 0;
    if (delay > 1000)
      delay = 1000;
    rc = poll(fds, 2, (int)delay);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      perror("poll");
      failed = 1;
      break;
    }
    if ((fds[0].revents | fds[1].revents) & (POLLNVAL | POLLHUP)) {
      failed = 1;
      break;
    }
    now = clock_ms();
    if (now < 0) {
      failed = 1;
      break;
    }
    if (fds[0].revents & POLLIN)
      for (unsigned i = 0; i < 64; ++i) {
        uint64_t received;
        nanoamt_relay_posix_stats before, after;
        nanoamt_relay_posix_get_stats(relay, &before);
        received = before.received;
        rc = nanoamt_relay_posix_receive(relay, now);
        nanoamt_relay_posix_get_stats(relay, &after);
        if (rc < 0) {
          fprintf(stderr, "relay input error %d\n", rc);
          failed = 1;
          break;
        }
        if (after.received == received)
          break;
      }
    if (failed)
      break;
    if (fds[1].revents & POLLIN)
      for (unsigned i = 0; i < 64; ++i) {
        nanoamt_native_packet packet;
        rc = nanoamt_native_receive(native, &packet);
        if (rc == NANOAMT_OK)
          break;
        if (rc < 0) {
          perror("native input");
          failed = 1;
          break;
        }
        if (rc == NANOAMT_PACKET) {
          rc = nanoamt_relay_posix_forward(relay, now, packet.ip, packet.size);
          if (rc < 0 && rc != NANOAMT_RELAY_ERROR_LIMIT) {
            failed = 1;
            break;
          }
        }
      }
    if (failed)
      break;
  }
  nanoamt_relay_posix_stats stats;
  nanoamt_relay_posix_get_stats(relay, &stats);
  fprintf(stderr, "AMT relay stopped: sent=%llu input_drops=%llu send_errors=%llu\n", (unsigned long long)stats.sent,
          (unsigned long long)stats.input_dropped, (unsigned long long)stats.send_errors);
  nanoamt_relay_posix_close(relay);
  nanoamt_native_close(native);
  return failed ? 1 : 0;
}
