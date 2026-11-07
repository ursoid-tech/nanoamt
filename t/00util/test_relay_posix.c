#define _GNU_SOURCE
#include "fixtures.h"
#include "nanoamt/relay_posix.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

static int blocked, fail_send, route_mtu;
static int fail_probe_pin;
static unsigned route_ifindex, route_queries, failed_probe_pins;
static uint8_t attempted[65577];
static size_t attempted_size;
static ssize_t relay_test_sendmsg(int fd, const struct msghdr *msg, int flags) {
  CHECK(msg->msg_iovlen == 1 && msg->msg_iov[0].iov_len <= sizeof(attempted));
  attempted_size = msg->msg_iov[0].iov_len;
  memcpy(attempted, msg->msg_iov[0].iov_base, attempted_size);
  if (route_mtu && attempted_size + (((const struct sockaddr *)msg->msg_name)->sa_family == AF_INET6 ? 48u : 28u) >
                       (unsigned)route_mtu) {
    route_ifindex = 0;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(msg); h; h = CMSG_NXTHDR((struct msghdr *)msg, h)) {
      if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO) {
        struct in_pktinfo info;
        memcpy(&info, CMSG_DATA(h), sizeof(info));
        route_ifindex = (unsigned)info.ipi_ifindex;
      } else if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO) {
        struct in6_pktinfo info;
        memcpy(&info, CMSG_DATA(h), sizeof(info));
        route_ifindex = info.ipi6_ifindex;
      }
    }
    CHECK(route_ifindex);
    errno = EMSGSIZE;
    return -1;
  }
  if (blocked || fail_send) {
    errno = blocked ? EAGAIN : EHOSTUNREACH;
    return -1;
  }
  return sendmsg(fd, msg, flags);
}
static int relay_test_getsockopt(int fd, int level, int name, void *value, socklen_t *size) {
  if (route_mtu && ((level == IPPROTO_IP && name == IP_MTU) || (level == IPPROTO_IPV6 && name == IPV6_MTU))) {
    CHECK(*size >= sizeof(int));
    uint32_t ifindex = 0;
    socklen_t index_size = sizeof(ifindex);
    CHECK(!getsockopt(fd, level, level == IPPROTO_IP ? IP_UNICAST_IF : IPV6_UNICAST_IF, &ifindex, &index_size));
    /* Model a second, larger route when the probe is not pinned to the
     * interface of the failed packet. Read the actual kernel socket option. */
    int mtu = ntohl(ifindex) == route_ifindex ? route_mtu : 65536;
    memcpy(value, &mtu, sizeof(mtu));
    *size = sizeof(int);
    ++route_queries;
    return 0;
  }
  return getsockopt(fd, level, name, value, size);
}
static int relay_test_setsockopt(int fd, int level, int name, const void *value, socklen_t size) {
  if (fail_probe_pin &&
      ((level == IPPROTO_IP && name == IP_UNICAST_IF) || (level == IPPROTO_IPV6 && name == IPV6_UNICAST_IF))) {
    ++failed_probe_pins;
    errno = EADDRNOTAVAIL;
    return -1;
  }
  return setsockopt(fd, level, name, value, size);
}
#define getsockopt relay_test_getsockopt
#define setsockopt relay_test_setsockopt
#define sendmsg relay_test_sendmsg
#include "../../lib/relay_posix.c"
#undef sendmsg
#undef getsockopt
#undef setsockopt

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
static void path_mtu(int outer6, int inner6) {
  nanoamt_relay_posix *r = open_relay(outer6);
  r->config.input_bytes = 16384;
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, outer6, inner6, 0);
  nanoamt_relay_posix_bound(r, &c.discovery);
  CHECK(inet_pton(outer6 ? AF_INET6 : AF_INET, outer6 ? "::1" : "127.0.0.2", c.discovery.ip) == 1);
  nanoamt_posix *g = nanoamt_posix_open(&c, 0);
  CHECK(g);
  nanoamt_packet packet;
  for (int phase = 0; phase < 2; ++phase) {
    CHECK(nanoamt_posix_send(g, 0) == NANOAMT_PACKET);
    readable(nanoamt_relay_posix_fd(r));
    CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_PACKET);
    CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_PACKET);
    readable(nanoamt_posix_fd(g));
    CHECK(nanoamt_posix_receive(g, 0, &packet) == NANOAMT_OK);
  }
  CHECK(nanoamt_posix_send(g, 0) == NANOAMT_PACKET);
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_OK);
  uint8_t fixture[128], bytes[1600];
  fixture_dual_data(fixture, &c, 0, 1);
  size_t header = inner6 ? 40 : 20, payload = 1400;
  size_t size = header + 8 + payload;
  memcpy(bytes, fixture + 2, header + 8);
  memset(bytes + header + 8, 0xa5, payload);
  put16(bytes + header + 4, (unsigned)(payload + 8));
  put16(bytes + header + 6, 0);
  put16(bytes + (inner6 ? 4 : 2), (unsigned)(inner6 ? payload + 8 : size));
  if (!inner6) {
    put16(bytes + 6, 0); /* fragmentation allowed */
    ip_checksum(bytes);
  }
  ip_packet ip;
  CHECK(nanoamt_ip_decode(bytes, size, &ip));
  put16(bytes + header + 6, nanoamt_checksum(bytes + header, payload + 8, nanoamt_pseudo_sum(&ip, 17, payload + 8)));
  route_mtu = 1280;
  route_queries = failed_probe_pins = 0;
  /* An unavailable interface must not let the probe fall back to a different
   * route and cache its MTU for this client. The next input can retry. */
  fail_probe_pin = 1;
  CHECK(!nanoamt_relay_posix_forward(r, 0, bytes, size));
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
  nanoamt_relay_posix_stats stats;
  nanoamt_relay_posix_get_stats(r, &stats);
  CHECK(failed_probe_pins == 1 && !route_queries);
  CHECK(!stats.path_mtu_updates && stats.send_errors == 1 && !stats.queued_inputs);
  no_data(nanoamt_posix_fd(g));
  fail_probe_pin = 0;
  CHECK(!nanoamt_relay_posix_forward(r, 0, bytes, size));
  CHECK(nanoamt_relay_posix_send(r, 0) == (inner6 ? NANOAMT_OK : NANOAMT_PACKET));
  nanoamt_relay_posix_get_stats(r, &stats);
  CHECK(route_queries == 1);
  CHECK(stats.path_mtu_updates == 1 && stats.send_errors == 2 && !stats.queued_inputs);
  if (inner6) {
    CHECK(stats.mtu_feedback == 1);
    no_data(nanoamt_posix_fd(g));
  } else {
    int rc;
    do {
      readable(nanoamt_posix_fd(g));
      rc = nanoamt_posix_receive(g, 0, &packet);
    } while (rc == NANOAMT_OK || rc == NANOAMT_IGNORED);
    CHECK(rc == NANOAMT_PACKET && packet.size == payload);
    for (size_t i = 0; i < payload; ++i)
      CHECK(packet.data[i] == 0xa5);
    CHECK(!stats.mtu_feedback);
  }
  route_mtu = 0;
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
static void asynchronous_error(void) {
  nanoamt_relay_posix *r = open_relay(0);
  nanoamt_endpoint ep;
  nanoamt_relay_posix_bound(r, &ep);
  ep.ip[0] = 127;
  ep.ip[3] = 1;
  struct sockaddr_storage address;
  socklen_t len = relay_sockaddr(&ep, &address);
  int client = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(client >= 0);
  uint8_t discovery[] = {1, 0, 0, 0, 0, 0, 0, 1};
  CHECK(sendto(client, discovery, sizeof(discovery), 0, (struct sockaddr *)&address, len) == sizeof(discovery));
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_PACKET);
  close(client); /* the reply will elicit ICMP Port Unreachable */
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_PACKET);
  struct pollfd p = {nanoamt_relay_posix_fd(r), POLLIN, 0};
  CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLERR));
  CHECK(nanoamt_relay_posix_send(r, 0) == NANOAMT_OK);
  CHECK(poll(&p, 1, 0) == 0);
  nanoamt_relay_posix_stats stats;
  nanoamt_relay_posix_get_stats(r, &stats);
  CHECK(stats.send_errors == 1);
  nanoamt_relay_posix_close(r);
}
static void multicast_control(void) {
  nanoamt_relay_posix *r = open_relay(0);
  nanoamt_endpoint ep;
  nanoamt_relay_posix_bound(r, &ep);
  struct ip_mreq request = {0};
  CHECK(inet_pton(AF_INET, "232.1.2.3", &request.imr_multiaddr) == 1);
  request.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(!setsockopt(nanoamt_relay_posix_fd(r), IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, sizeof(request)));
  memcpy(ep.ip, &request.imr_multiaddr, 4);
  struct sockaddr_storage address;
  socklen_t len = relay_sockaddr(&ep, &address);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(fd >= 0);
  CHECK(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &request.imr_interface, sizeof(request.imr_interface)));
  uint8_t discovery[] = {1, 0, 0, 0, 0, 0, 0, 1};
  CHECK(sendto(fd, discovery, sizeof(discovery), 0, (struct sockaddr *)&address, len) == sizeof(discovery));
  readable(nanoamt_relay_posix_fd(r));
  CHECK(nanoamt_relay_posix_receive(r, 0) == NANOAMT_IGNORED);
  CHECK(!nanoamt_relay_posix_wants_write(r));
  close(fd);
  nanoamt_relay_posix_close(r);
}
int main(void) {
  for (int outer = 0; outer < 2; ++outer)
    for (int inner = 0; inner < 2; ++inner)
      path_mtu(outer, inner);
  for (int outer6 = 0; outer6 < 2; ++outer6)
    for (int inner6 = 0; inner6 < 2; ++inner6)
      exchange(outer6, inner6);
  admission(0);
  admission(1);
  asynchronous_error();
  multicast_control();
  puts("relay-posix: real UDP, backpressure, withdrawal, expiry and admission passed");
  return 0;
}
