#define _GNU_SOURCE
#include "fixtures.h"
#include "nanoamt/native.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>

static int fail_filter;
static int test_setsockopt(int fd, int level, int option, const void *value, socklen_t size) {
  if (option == MCAST_MSFILTER && fail_filter && !--fail_filter) {
    errno = ENOMEM;
    return -1;
  }
  return setsockopt(fd, level, option, value, size);
}
#define setsockopt test_setsockopt
#include "../../lib/native_linux.c"
#undef setsockopt

static nanoamt_memberships *state(void) {
  nanoamt_membership_config c = {0};
  c.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  nanoamt_memberships *s = nanoamt_memberships_new(&c, 0);
  CHECK(s);
  return s;
}
static void membership(nanoamt_memberships *s, const nanoamt_config *c, enum report_type type) {
  nanoamt_datagram report;
  uint8_t mac[6] = {0}, nonce[4] = {0};
  nanoamt_report_encode(&report, c, mac, nonce, type);
  CHECK(!nanoamt_memberships_apply(s, 0, report.bytes + 12, report.size - 12, c->ip_version == 6 ? 6 : 4));
}
static void exclude_source(nanoamt_memberships *s, nanoamt_config config) {
  config.any_source = 0;
  nanoamt_datagram report;
  uint8_t mac[6] = {0}, nonce[4] = {0};
  nanoamt_report_encode(&report, &config, mac, nonce, REPORT_CURRENT);
  uint8_t *ip = report.bytes + 12, *record = ip + (config.ip_version == 6 ? 48 : 24);
  record[8] = 2; /* MODE_IS_EXCLUDE with one blocked source */
  put16(record + 2, 0);
  ip_packet view;
  CHECK(nanoamt_ip_decode(ip, report.size - 12, &view));
  put16(record + 2, nanoamt_checksum(record, view.payload_size,
                                     config.ip_version == 6 ? nanoamt_pseudo_sum(&view, 58, view.payload_size) : 0));
  CHECK(!nanoamt_memberships_apply(s, 0, ip, report.size - 12, config.ip_version == 6 ? 6 : 4));
}
static void codec(void) {
  for (int v6 = 0; v6 < 2; ++v6) {
    unsigned random = 0;
    nanoamt_config c = fixture_dual_config(&random, 0, v6, 0);
    uint8_t packet[128], original[128];
    size_t size = fixture_dual_data(packet, &c, 1, 1) - 2;
    memcpy(original, packet, sizeof(original));
    size_t checksum = v6 ? 48 + 6 : 24 + 6;
    put16(packet + 2 + checksum, 1234); /* kernel's unfinished checksum */
    CHECK(native_fix_offload(packet + 2, size));
    CHECK(!memcmp(packet, original, size + 2));
    put16(packet + 2 + (v6 ? 48 : 24) + 4, 65535);
    CHECK(!native_fix_offload(packet + 2, size));
    size = fixture_dual_data(packet, &c, 0, 1) - 2;
    uint8_t *ip = packet + 2;
    if (!v6) {
      put16(ip + 6, 1);
      ip_checksum(ip);
      CHECK(!native_fix_offload(ip, size));
    } else {
      memmove(ip + 48, ip + 40, 13);
      memset(ip + 40, 0, 8);
      ip[6] = 44;
      ip[40] = 17;
      put16(ip + 42, 8);
      put16(ip + 4, 21);
      CHECK(!native_fix_offload(ip, size + 8));
    }
    /* Independent TCP checksum expectation, including options. */
    size_t header = v6 ? 40 : 20;
    memset(ip, 0, 100);
    ip[0] = v6 ? 0x60 : 0x45;
    ip[v6 ? 6 : 9] = 6;
    ip[v6 ? 7 : 8] = 64;
    memcpy(ip + (v6 ? 8 : 12), c.source, v6 ? 16 : 4);
    memcpy(ip + (v6 ? 24 : 16), c.group, v6 ? 16 : 4);
    put16(ip + (v6 ? 4 : 2), v6 ? 25 : (unsigned)header + 25);
    if (!v6)
      ip_checksum(ip);
    uint8_t *tcp = ip + header;
    tcp[12] = 0x60;
    tcp[24] = 55;
    tcp[16] = 0xa5;
    CHECK(native_fix_offload(ip, header + 25));
    uint32_t sum = 6 + 25;
    for (size_t i = v6 ? 8 : 12; i < (v6 ? 40u : 20u); i += 2)
      sum += read16(ip + i);
    CHECK(!nanoamt_checksum(tcp, 25, sum));
    tcp[12] = 0xf0;
    CHECK(!native_fix_offload(ip, header + 25));
  }
  puts("native: offload UDP/TCP checksums and fragment rejection passed");
}
static int source_socket(const nanoamt_config *c, unsigned interface) {
  int v6 = c->ip_version == 6;
  int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  CHECK(fd >= 0);
  struct sockaddr_storage address;
  native_address(&address, c->source, v6 ? 6 : 4, interface);
  CHECK(!bind(fd, (struct sockaddr *)&address, v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)));
  if (v6)
    CHECK(!setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface, sizeof(interface)));
  else {
    struct ip_mreqn request = {0};
    request.imr_ifindex = (int)interface;
    CHECK(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &request, sizeof(request)));
  }
  return fd;
}
static void emit(int fd, const nanoamt_config *c, unsigned interface) {
  struct sockaddr_storage address;
  native_address(&address, c->group, c->ip_version == 6 ? 6 : 4, interface);
  if (c->ip_version == 6)
    ((struct sockaddr_in6 *)&address)->sin6_port = htons(c->port);
  else
    ((struct sockaddr_in *)&address)->sin_port = htons(c->port);
  ssize_t n = sendto(fd, "native-amt", 10, 0, (struct sockaddr *)&address,
                     c->ip_version == 6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
  if (n < 0)
    perror("native source sendto");
  CHECK(n == 10);
}
static int expected_outgoing = -1;
static int receive_until(nanoamt_native *n, int wanted) {
  int count = 0;
  for (int i = 0; i < 100; ++i) {
    struct pollfd p = {nanoamt_native_fd(n), POLLIN, 0};
    CHECK(poll(&p, 1, 10) >= 0);
    nanoamt_native_packet packet;
    int rc = nanoamt_native_receive(n, &packet);
    CHECK(rc >= 0);
    if (rc == NANOAMT_PACKET) {
      CHECK(expected_outgoing < 0 || packet.outgoing == expected_outgoing);
      ip_packet ip;
      CHECK(nanoamt_ip_decode(packet.ip, packet.size, &ip));
      CHECK(ip.protocol == 17 && ip.payload_size == 18 && !memcmp(ip.payload + 8, "native-amt", 10));
      CHECK(!nanoamt_checksum(ip.payload, 18, nanoamt_pseudo_sum(&ip, 17, 18)));
      ++count;
      if (wanted)
        return count;
    }
  }
  return count;
}
static void feedback(nanoamt_native *n, const nanoamt_config *c) {
  int v6 = c->ip_version == 6;
  int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW | SOCK_NONBLOCK, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
  CHECK(fd >= 0);
  uint8_t packet[1600];
  size_t size = fixture_dual_data(packet, c, 0, 1) - 2;
  nanoamt_native_mtu_feedback(n, 0, packet + 2, size, v6 ? 1280 : 1400);
  struct pollfd p = {fd, POLLIN, 0};
  CHECK(poll(&p, 1, 1000) == 1);
  uint8_t reply[1500];
  struct sockaddr_storage sender = {0};
  socklen_t sender_size = sizeof(sender);
  ssize_t bytes = recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr *)&sender, &sender_size);
  CHECK(bytes > 0);
  size_t at = v6 ? 0 : (reply[0] & 15u) * 4u;
  CHECK((size_t)bytes == at + 8 + size);
  CHECK(reply[at] == (v6 ? 2 : 3) && reply[at + 1] == (v6 ? 0 : 4));
  CHECK(read16(reply + at + 6) == (v6 ? 1280 : 1400));
  CHECK(!memcmp(reply + at + 8, packet + 2, size));
  if (!v6)
    CHECK(!nanoamt_checksum(reply + at, (size_t)bytes - at, 0));
  else {
    ip_packet view = {0};
    view.version = 6;
    view.source = (uint8_t *)&((struct sockaddr_in6 *)&sender)->sin6_addr;
    view.destination = (uint8_t *)c->source;
    CHECK(!nanoamt_checksum(reply, (size_t)bytes, nanoamt_pseudo_sum(&view, 58, (size_t)bytes)));
  }
  nanoamt_native_mtu_feedback(n, 0, packet + 2, size, v6 ? 1280 : 1400);
  nanoamt_native_stats stats;
  nanoamt_native_get_stats(n, &stats);
  CHECK(stats.feedback_sent == 1 && stats.feedback_limited == 1 && !stats.feedback_errors);
  /* Large quotes are bounded to the minimum error-message MTU; preserve the
   * actual IPv6 tunnel budget even when it is below the host's minimum PMTU. */
  memset(packet + 2 + size, 0x5a, 1500 - size);
  size = 1500;
  put16(packet + 2 + (v6 ? 4 : 2), v6 ? 1460 : 1500);
  if (!v6)
    ip_checksum(packet + 2);
  nanoamt_native_mtu_feedback(n, 1000, packet + 2, size, v6 ? 1230 : 1400);
  CHECK(poll(&p, 1, 1000) == 1);
  bytes = recv(fd, reply, sizeof(reply), 0);
  CHECK(bytes == (v6 ? 1240 : 576));
  at = v6 ? 0 : (reply[0] & 15u) * 4u;
  CHECK(read16(reply + at + 6) == (v6 ? 1230 : 1400));
  CHECK(!memcmp(reply + at + 8, packet + 2, v6 ? 1232 : 548));
  if (!v6)
    CHECK(!nanoamt_checksum(reply + at, (size_t)bytes - at, 0));
  close(fd);
}
static void network(int v6, const char *interface_name) {
  unsigned random = 0, interface = if_nametoindex(interface_name);
  CHECK(interface);
  nanoamt_config c = fixture_dual_config(&random, 0, v6, 0);
  if (v6)
    CHECK(inet_pton(AF_INET6, "2001:db8::a", c.source) == 1);
  nanoamt_native_config config = {0};
  config.interface_index = interface;
  config.feedback_burst = 1;
  nanoamt_native *n = nanoamt_native_open(&config);
  if (!n)
    perror("native_open");
  CHECK(n);
  nanoamt_memberships *s = state();
  membership(s, &c, REPORT_JOIN);
  CHECK(!nanoamt_native_reconcile(n, s));
  native_filter *old = n->filters;
  CHECK(!nanoamt_native_reconcile(n, s) && n->filters == old); /* no duplicate joins */
  int fd = source_socket(&c, interface);
  nanoamt_config alternate = c;
  CHECK(inet_pton(v6 ? AF_INET6 : AF_INET, v6 ? "2001:db8::b" : "192.0.2.20", alternate.source) == 1);
  int other_fd = source_socket(&alternate, interface);
  expected_outgoing = !n->loopback;
  emit(fd, &c, interface);
  CHECK(receive_until(n, 1) == 1);
  emit(other_fd, &alternate, interface);
  CHECK(!receive_until(n, 0)); /* source not present in INCLUDE */
  if (!n->loopback) {
    nanoamt_config remote = c;
    CHECK(inet_pton(v6 ? AF_INET6 : AF_INET, v6 ? "2001:db8::c" : "192.0.2.30", remote.source) == 1);
    nanoamt_memberships *incoming = state();
    membership(incoming, &remote, REPORT_JOIN);
    CHECK(!nanoamt_native_reconcile(n, incoming));
    unsigned peer_interface = if_nametoindex("peer0");
    CHECK(peer_interface);
    int remote_fd = source_socket(&remote, peer_interface);
    expected_outgoing = 0;
    emit(remote_fd, &remote, peer_interface);
    CHECK(receive_until(n, 1) == 1);
    close(remote_fd);
    nanoamt_memberships_free(incoming);
    CHECK(!nanoamt_native_reconcile(n, s));
    old = n->filters;
    expected_outgoing = 1;
  }

  nanoamt_config second = c;
  ++second.group[v6 ? 15 : 3];
  membership(s, &second, REPORT_JOIN);
  nanoamt_config third = second;
  ++third.group[v6 ? 15 : 3];
  membership(s, &third, REPORT_JOIN);
  fail_filter = 2; /* fail after one replacement socket already joined */
  CHECK(nanoamt_native_reconcile(n, s) == NANOAMT_ERROR_IO);
  CHECK(n->filters == old && n->count == 1);
  emit(fd, &c, interface);
  CHECK(receive_until(n, 1) == 1);
  int original_fd = n->filters[0].fd;
  CHECK(!nanoamt_native_reconcile(n, s) && n->count == 3);
  CHECK(n->filters[0].fd == original_fd); /* unchanged group socket is retained */
  emit(fd, &second, interface);
  CHECK(receive_until(n, 1) == 1);

  /* INCLUDE -> EXCLUDE(empty) -> INCLUDE(empty), releasing the native join. */
  c.any_source = 1;
  membership(s, &c, REPORT_JOIN);
  CHECK(!nanoamt_native_reconcile(n, s));
  emit(fd, &c, interface);
  CHECK(receive_until(n, 1) == 1);
  emit(other_fd, &alternate, interface);
  CHECK(receive_until(n, 1) == 1);
  exclude_source(s, c);
  CHECK(!nanoamt_native_reconcile(n, s));
  emit(fd, &c, interface);
  CHECK(!receive_until(n, 0)); /* explicit EXCLUDE block */
  emit(other_fd, &alternate, interface);
  CHECK(receive_until(n, 1) == 1);
  membership(s, &c, REPORT_LEAVE);
  membership(s, &second, REPORT_LEAVE);
  membership(s, &third, REPORT_LEAVE);
  CHECK(!nanoamt_native_reconcile(n, s) && !n->count);
  (void)receive_until(n, 0); /* drain old packets */
  emit(fd, &c, interface);
  CHECK(!receive_until(n, 0));
  feedback(n, &c);
  nanoamt_native_stats stats;
  nanoamt_native_get_stats(n, &stats);
  CHECK(stats.failed_transactions == 1 && !stats.groups && !stats.sources);
  nanoamt_memberships_free(s);
  close(fd);
  close(other_fd);
  nanoamt_native_close(n);
  printf("native: IPv%d %s capture, transactional filters and ICMP passed\n", v6 ? 6 : 4, interface_name);
}
int main(int argc, char **argv) {
  CHECK(argc >= 2);
  if (!strcmp(argv[1], "codec"))
    codec();
  else {
    CHECK(argc == 4);
    network(atoi(argv[2]), argv[3]);
  }
  return 0;
}
