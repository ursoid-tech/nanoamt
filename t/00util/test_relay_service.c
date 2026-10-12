#define _GNU_SOURCE
#include "fixtures.h"
#include "nanoamt/posix.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

static int64_t clock_ms(void) {
  struct timespec t;
  CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
  CHECK(argc == 3);
  int outer6 = atoi(argv[1]), inner6 = atoi(argv[2]);
  unsigned random = 0, interface = if_nametoindex("native0");
  CHECK(interface);
  nanoamt_config config = fixture_dual_config(&random, outer6, inner6, 0);
  config.random_bytes = NULL;
  config.ecn = 1;
  if (outer6)
    CHECK(inet_pton(AF_INET6, "::1", config.discovery.ip) == 1);
  else
    CHECK(inet_pton(AF_INET, "127.0.0.1", config.discovery.ip) == 1);
  if (inner6)
    CHECK(inet_pton(AF_INET6, "2001:db8::a", config.source) == 1);
  int source = socket(inner6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  CHECK(source >= 0);
  struct sockaddr_storage address = {0};
  socklen_t len;
  if (inner6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
    a->sin6_family = AF_INET6;
    memcpy(&a->sin6_addr, config.source, 16);
    len = sizeof(*a);
    CHECK(!bind(source, (struct sockaddr *)a, len));
    CHECK(!setsockopt(source, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface, sizeof(interface)));
    memcpy(&a->sin6_addr, config.group, 16);
    a->sin6_port = htons(config.port);
    a->sin6_scope_id = interface;
  } else {
    struct sockaddr_in *a = (struct sockaddr_in *)&address;
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr, config.source, 4);
    len = sizeof(*a);
    CHECK(!bind(source, (struct sockaddr *)a, len));
    struct ip_mreqn request = {0};
    request.imr_ifindex = (int)interface;
    CHECK(!setsockopt(source, IPPROTO_IP, IP_MULTICAST_IF, &request, sizeof(request)));
    int pmtu = IP_PMTUDISC_DONT;
    CHECK(!setsockopt(source, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu)));
    memcpy(&a->sin_addr, config.group, 4);
    a->sin_port = htons(config.port);
  }
  int tos = 2;
  CHECK(!setsockopt(source, inner6 ? IPPROTO_IPV6 : IPPROTO_IP, inner6 ? IPV6_TCLASS : IP_TOS, &tos, sizeof(tos)));
  int64_t now = clock_ms(), start = now;
  nanoamt_posix *gateway = nanoamt_posix_open(&config, now);
  CHECK(gateway);
  uint8_t payload[2000];
  size_t payload_size = inner6 ? 1200 : sizeof(payload);
  for (size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = (uint8_t)(i * 37 + 11);
  int received = 0;
  while (clock_ms() - start < 6000) {
    now = clock_ms();
    CHECK(nanoamt_posix_send(gateway, now) >= 0);
    if (nanoamt_posix_get_state(gateway) == NANOAMT_STATE_CLOSED)
      break;
    if (!received && nanoamt_posix_is_joined(gateway))
      CHECK(sendto(source, payload, payload_size, 0, (struct sockaddr *)&address, len) == (ssize_t)payload_size);
    struct pollfd p = {nanoamt_posix_fd(gateway), POLLIN, 0};
    CHECK(poll(&p, 1, 10) >= 0);
    nanoamt_packet packet;
    int rc = nanoamt_posix_receive(gateway, clock_ms(), &packet);
    CHECK(rc >= 0);
    if (rc == NANOAMT_PACKET) {
      CHECK(packet.size == payload_size && !memcmp(packet.data, payload, payload_size));
      CHECK(packet.source.ip_version == (inner6 ? 6 : 4));
      CHECK(!memcmp(packet.source.ip, config.source, inner6 ? 16 : 4));
      CHECK(!memcmp(packet.destination.ip, config.group, inner6 ? 16 : 4));
      CHECK(packet.destination.port == config.port && packet.source.port && packet.source.port != config.port);
      CHECK((packet.tos & 3u) == 2);
      if (!received) {
        received = 1;
        CHECK(!nanoamt_posix_leave(gateway, clock_ms()));
      }
    }
  }
  CHECK(received && nanoamt_posix_get_state(gateway) == NANOAMT_STATE_CLOSED);
  nanoamt_posix_close(gateway);
  close(source);
  printf("service: outer IPv%d inner IPv%d native multicast delivery and leave passed\n", outer6 ? 6 : 4,
         inner6 ? 6 : 4);
  return 0;
}
