#define _POSIX_C_SOURCE 200809L
#include "nanoamt/posix.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) {
  (void)sig;
  stopping = 1;
}
static int64_t now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
    perror("clock_gettime");
    exit(1);
  }
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr,
            "usage: %s RELAY SOURCE|- GROUP UDP_PORT\n"
            "IPv4/IPv6 numeric addresses; '-' selects ASM; port 0 selects complete IP packets.\n"
            "stdout: each packet prefixed with its 4-byte big-endian length\n",
            argv[0]);
    return 2;
  }
  nanoamt_config config = {0};
  char *end;
  unsigned long port = strtoul(argv[4], &end, 10);
  if (!*argv[4] || *end || port > 65535)
    return 2;
  int inner_family = AF_INET;
  if (inet_pton(AF_INET, argv[3], config.group) != 1) {
    inner_family = AF_INET6;
    config.ip_version = 6;
    if (inet_pton(AF_INET6, argv[3], config.group) != 1)
      return 2;
  }
  config.any_source = strcmp(argv[2], "-") == 0;
  if (!config.any_source && inet_pton(inner_family, argv[2], config.source) != 1)
    return 2;
  struct addrinfo hints = {0}, *resolved = NULL;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  if (getaddrinfo(argv[1], "2268", &hints, &resolved))
    return 2;
  if (resolved->ai_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)resolved->ai_addr;
    config.discovery.ip_version = 6;
    config.discovery.scope_id = v6->sin6_scope_id;
    memcpy(config.discovery.ip, &v6->sin6_addr, 16);
  } else
    memcpy(config.discovery.ip, &((const struct sockaddr_in *)resolved->ai_addr)->sin_addr, 4);
  freeaddrinfo(resolved);
  config.discovery.port = NANOAMT_PORT;
  config.port = (uint16_t)port;
  nanoamt_posix *io = nanoamt_posix_open(&config, now_ms());
  if (!io) {
    perror("nanoamt_posix_open");
    return 1;
  }
  signal(SIGINT, stop);
  signal(SIGTERM, stop);
  int leaving = 0, result = 0;
  for (;;) {
    int64_t now = now_ms();
    if (stopping && !leaving) {
      nanoamt_posix_leave(io, now);
      leaving = 1;
    }
    int ret = nanoamt_posix_send(io, now);
    if (ret < 0) {
      fprintf(stderr, "AMT send failed: %d\n", ret);
      result = 1;
      break;
    }
    if (nanoamt_posix_get_state(io) == NANOAMT_STATE_CLOSED)
      break;
    struct pollfd fd = {nanoamt_posix_fd(io), POLLIN, 0};
    if (nanoamt_posix_wants_write(io))
      fd.events |= POLLOUT;
    int64_t deadline = nanoamt_posix_next_timeout(io);
    int timeout = deadline <= now ? 0 : deadline - now > 1000 ? 1000 : (int)(deadline - now);
    ret = poll(&fd, 1, timeout);
    if (ret < 0 && errno == EINTR)
      continue;
    if (ret < 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      result = 1;
      break;
    }
    if (fd.revents & POLLIN) {
      nanoamt_packet packet;
      ret = nanoamt_posix_receive(io, now_ms(), &packet);
      if (ret < 0) {
        fprintf(stderr, "AMT receive failed: %d\n", ret);
        result = 1;
        break;
      }
      if (ret == NANOAMT_PACKET) {
        uint8_t *bytes = config.port ? packet.data : packet.ip_data;
        size_t size = config.port ? packet.size : packet.ip_size;
        uint32_t length = htonl((uint32_t)size);
        if (fwrite(&length, 1, 4, stdout) != 4 || fwrite(bytes, 1, size, stdout) != size || fflush(stdout)) {
          result = 1;
          break;
        }
      }
    }
  }
  nanoamt_posix_close(io);
  return result;
}
