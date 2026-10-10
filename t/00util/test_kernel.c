#define _POSIX_C_SOURCE 200809L
#include "nanoamt/posix.h"
#include "fixtures.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

static int64_t clock_ms(void) {
  struct timespec t;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
  CHECK(argc == 3);
  int inner6 = atoi(argv[1]), any_source = atoi(argv[2]);
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, 0, inner6, any_source);
  memcpy(c.discovery.ip, "\x0a\x00\x00\x01", 4);
  c.random_bytes = NULL;
  int source = socket(inner6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  CHECK(source >= 0);
  struct sockaddr_storage target = {0};
  socklen_t length;
  if (inner6) {
    struct sockaddr_in6 address = {0};
    address.sin6_family = AF_INET6;
    memcpy(&address.sin6_addr, c.source, 16);
    CHECK(bind(source, (struct sockaddr *)&address, sizeof(address)) == 0);
    unsigned index = if_nametoindex("amtr");
    CHECK(index && setsockopt(source, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index)) == 0);
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&target;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(c.port);
    v6->sin6_scope_id = index;
    memcpy(&v6->sin6_addr, c.group, 16);
    length = sizeof(*v6);
  } else {
    struct in_addr address;
    memcpy(&address, c.source, 4);
    CHECK(setsockopt(source, IPPROTO_IP, IP_MULTICAST_IF, &address, sizeof(address)) == 0);
    struct sockaddr_in *v4 = (struct sockaddr_in *)&target;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(c.port);
    memcpy(&v4->sin_addr, c.group, 4);
    length = sizeof(*v4);
  }
  int64_t start = clock_ms();
  nanoamt_posix *io = nanoamt_posix_open(&c, start);
  CHECK(io);
  int received = 0;
  while (clock_ms() - start < 5000) {
    CHECK(nanoamt_posix_send(io, clock_ms()) >= 0);
    if (nanoamt_posix_get_state(io) == NANOAMT_STATE_CLOSED)
      break;
    if (!received && nanoamt_posix_is_joined(io))
      CHECK(sendto(source, "kernel-amt", 10, 0, (struct sockaddr *)&target, length) == 10);
    struct pollfd fd = {nanoamt_posix_fd(io), POLLIN, 0};
    CHECK(poll(&fd, 1, 10) >= 0);
    nanoamt_packet packet;
    int ret = nanoamt_posix_receive(io, clock_ms(), &packet);
    CHECK(ret >= 0);
    if (ret == NANOAMT_PACKET) {
      CHECK(packet.size == 10 && memcmp(packet.data, "kernel-amt", 10) == 0);
      CHECK(packet.destination.ip_version == (inner6 ? 6 : 4));
      if (!received) {
        received = 1;
        CHECK(nanoamt_posix_leave(io, clock_ms()) == NANOAMT_OK);
      }
    }
  }
  if (!received || nanoamt_posix_get_state(io) != NANOAMT_STATE_CLOSED)
    fprintf(stderr, "received=%d state=%d\n", received, nanoamt_posix_get_state(io));
  CHECK(received && nanoamt_posix_get_state(io) == NANOAMT_STATE_CLOSED);
  nanoamt_posix_close(io);
  close(source);
  printf("kernel: IPv%d %s membership and multicast delivery passed\n", inner6 ? 6 : 4, any_source ? "ASM" : "SSM");
  return 0;
}
