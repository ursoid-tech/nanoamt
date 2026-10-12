#define _GNU_SOURCE
#include "fixtures.h"
#include "nanoamt/relay_posix.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

static int blocked, fail_send;
static uint8_t attempted[65577];
static size_t attempted_size;
static ssize_t relay_test_sendmsg(int fd, const struct msghdr *msg, int flags) {
  CHECK(msg->msg_iovlen == 1 && msg->msg_iov[0].iov_len <= sizeof(attempted));
  attempted_size = msg->msg_iov[0].iov_len;
  memcpy(attempted, msg->msg_iov[0].iov_base, attempted_size);
  if (blocked || fail_send) {
    errno = blocked ? EAGAIN : EHOSTUNREACH;
    return -1;
  }
  return sendmsg(fd, msg, flags);
}
#define sendmsg relay_test_sendmsg
#include "../../lib/relay_posix.c"
#undef sendmsg

/* TEST ONLY: production callers supply a cryptographic MAC provider. */
static int test_mac(void *ctx, const uint8_t key[32], const uint8_t *bytes, size_t size, uint8_t out[6]) {
  (void)ctx;
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < 32; ++i)
    hash = (hash ^ key[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < size; ++i)
    hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < 6; ++i) {
    out[i] = (uint8_t)hash;
    hash >>= 8;
  }
  return 0;
}
static void readable(int fd) {
  struct pollfd p = {fd, POLLIN, 0};
  CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
}
static void no_data(int fd) {
  struct pollfd p = {fd, POLLIN, 0};
  CHECK(poll(&p, 1, 0) == 0);
}
static nanoamt_relay_posix *open_relay(int outer6) {
  nanoamt_relay_posix_config c = {0};
  c.listen.ip_version = outer6 ? 6 : 4;
  c.relay.response_mac = test_mac;
  c.input_capacity = 2;
  c.input_bytes = 128;
  c.control_capacity = 2;
  nanoamt_relay_posix *r = nanoamt_relay_posix_open(&c, 0);
  CHECK(r);
  return r;
}
static void exchange(int outer6, int inner6) {
  nanoamt_relay_posix *r = open_relay(outer6);
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, outer6, inner6, 0);
  nanoamt_relay_posix_bound(r, &c.discovery);
  if (outer6)
    CHECK(inet_pton(AF_INET6, "::1", c.discovery.ip) == 1);
  else
    CHECK(inet_pton(AF_INET, "127.0.0.2", c.discovery.ip) == 1);
  c.ecn = 1;
  nanoamt_posix *g = nanoamt_posix_open(&c, 0);
  CHECK(g);
  nanoamt_packet packet;
  for (int phase = 0; phase < 2; ++phase) {
    CHECK(nanoamt_posix_send(g, 0) == NANOAMT_PACKET);
    readable(nanoamt_relay_posix_fd(r));
    CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_PACKET);
    blocked = 1;
    CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
    uint8_t saved[128];
    size_t saved_size = attempted_size;
    CHECK(saved_size <= sizeof(saved));
    memcpy(saved, attempted, saved_size);
    CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
    CHECK(saved_size == attempted_size && !memcmp(saved, attempted, saved_size));
    blocked = 0;
    CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_PACKET);
    readable(nanoamt_posix_fd(g));
    CHECK(nanoamt_posix_receive(g, 0, &packet) == NANOAMT_OK);
  }
  CHECK(nanoamt_posix_send(g, 0) == NANOAMT_PACKET);
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_OK);
  CHECK(nanoamt_posix_is_joined(g));
  nanoamt_relay_stats core_stats;
  nanoamt_relay_get_stats(nanoamt_relay_posix_core(r), &core_stats);
  CHECK(core_stats.clients == 1);
  uint8_t wrapped[128], saved[128];
  size_t size = fixture_dual_data(wrapped, &c, 0, 1);
  if (inner6)
    wrapped[3] |= 0x20; /* inner ECT(0), copied to outer TCLASS */
  else {
    wrapped[3] |= 2;
    ip_checksum(wrapped + 2);
  }
  memcpy(saved, wrapped, size);
  CHECK(nanoamt_relay_posix_forward(r, 0, wrapped + 2, size - 2) == NANOAMT_OK);
  memset(wrapped, 0, sizeof(wrapped)); /* the adapter owns its copy */
  blocked = 1;
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
  CHECK(attempted_size == size && !memcmp(attempted, saved, size));
  CHECK(nanoamt_relay_posix_wants_write(r));
  CHECK(nanoamt_relay_posix_next_timeout(r) == 1000);
  blocked = 0;
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_PACKET);
  readable(nanoamt_posix_fd(g));
  CHECK(nanoamt_posix_receive(g, 0, &packet) == NANOAMT_PACKET);
  CHECK(packet.size == 5 && packet.source.port == 1234);
  CHECK((packet.tos & 3u) == 2);
  CHECK(!nanoamt_relay_posix_wants_write(r));

  /* Permanent errors consume only that output; subsequent packets still work. */
  CHECK(nanoamt_relay_posix_forward(r, 0, saved + 2, size - 2) == NANOAMT_OK);
  fail_send = 1;
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
  CHECK(!nanoamt_relay_posix_wants_write(r));
  fail_send = 0;
  no_data(nanoamt_posix_fd(g));

  /* Input count and byte bounds, and independent deadline expiry. */
  CHECK(nanoamt_relay_posix_forward(r, 0, saved + 2, size - 2) == NANOAMT_OK);
  CHECK(nanoamt_relay_posix_forward(r, 0, saved + 2, size - 2) == NANOAMT_OK);
  CHECK(nanoamt_relay_posix_forward(r, 0, saved + 2, size - 2) == NANOAMT_RELAY_ERROR_LIMIT);
  CHECK(nanoamt_relay_posix_send(r, 1000) == NANOAMT_OK);
  CHECK(!nanoamt_relay_posix_wants_write(r));
  no_data(nanoamt_posix_fd(g));

  /* A queued frame must be revoked after receiving the leave report. */
  CHECK(nanoamt_relay_posix_forward(r, 1000, saved + 2, size - 2) == NANOAMT_OK);
  blocked = 1;
  CHECK(nanoamt_relay_posix_send(r, 1000) == NANOAMT_OK);
  CHECK(nanoamt_posix_leave(g, 1000) == NANOAMT_OK);
  CHECK(nanoamt_posix_send(g, 1000) == NANOAMT_PACKET);
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 1000) == NANOAMT_OK);
  blocked = 0;
  CHECK(nanoamt_relay_posix_send(r, 1000) == NANOAMT_OK);
  no_data(nanoamt_posix_fd(g));
  nanoamt_relay_posix_stats stats;
  nanoamt_relay_posix_get_stats(r, &stats);
  CHECK(stats.revoked == 1 && stats.expired == 2 && stats.input_dropped == 1 && stats.send_errors == 1);
  CHECK(!stats.queued_inputs && !stats.retained_input_bytes);
  CHECK(nanoamt_relay_posix_send(r, 999) == NANOAMT_ERROR_ARGUMENT);
  nanoamt_posix_close(g);
  nanoamt_relay_posix_close(r);
}
static void admission(int per_source) {
  nanoamt_relay_posix_config c = {0};
  c.relay.response_mac = test_mac;
  c.control_burst = 2;
  c.control_rate = 1;
  c.control_capacity = 1;
  if (per_source) {
    c.control_burst = 100;
    c.source_rate = 1;
    c.source_burst = 2;
  }
  nanoamt_relay_posix *r = nanoamt_relay_posix_open(&c, 0);
  CHECK(r);
  nanoamt_endpoint ep;
  nanoamt_relay_posix_bound(r, &ep);
  ep.ip[0] = 127;
  ep.ip[3] = 1;
  struct sockaddr_storage address;
  socklen_t len = relay_sockaddr(&ep, &address);
  int fd = socket(AF_INET, SOCK_DGRAM, 0), other = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(fd >= 0 && other >= 0);
  uint8_t discovery[] = {1, 0, 0, 0, 0, 0, 0, 1};
  for (int i = 0; i < 3; ++i) {
    /* Different UDP source ports still share the same source-IP quota. */
    int sender = per_source && i == 2 ? other : fd;
    CHECK(sendto(sender, discovery, sizeof(discovery), 0, (struct sockaddr *)&address, len) == sizeof(discovery));
    readable(nanoamt_relay_posix_fd(r));
    CHECK(nanoamt_relay_posix_receive(r, 0) == (i == 0 ? NANOAMT_PACKET : NANOAMT_IGNORED));
  }
  nanoamt_relay_posix_stats stats;
  nanoamt_relay_posix_get_stats(r, &stats);
  CHECK(stats.control_dropped == 1 && stats.rate_limited == 1 && stats.queued_controls == 1);
  CHECK(nanoamt_relay_posix_send(r, 5000) == NANOAMT_OK);
  no_data(fd);
  CHECK(sendto(fd, discovery, sizeof(discovery), 0, (struct sockaddr *)&address, len) == sizeof(discovery));
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 5000) == NANOAMT_PACKET);
  CHECK(nanoamt_relay_posix_send(r, 5000) == NANOAMT_PACKET);
  readable(fd);
  close(fd);
  close(other);
  nanoamt_relay_posix_close(r);
}
int main(void) {
  for (int outer6 = 0; outer6 < 2; ++outer6)
    for (int inner6 = 0; inner6 < 2; ++inner6)
      exchange(outer6, inner6);
  admission(0);
  admission(1);
  puts("relay-posix: real UDP, backpressure, withdrawal, expiry and admission passed");
  return 0;
}
