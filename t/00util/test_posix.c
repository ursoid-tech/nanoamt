#define _POSIX_C_SOURCE 200809L
#include "fixtures.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

static int block_sends;
static uint8_t attempted[128];
static size_t attempted_size;

static ssize_t test_sendto(int fd, const void *bytes, size_t size, int flags, const struct sockaddr *to,
                           socklen_t to_size) {
  CHECK(size <= sizeof(attempted));
  memcpy(attempted, bytes, size);
  attempted_size = size;
  if (block_sends) {
    errno = EAGAIN;
    return -1;
  }
  return sendto(fd, bytes, size, flags, to, to_size);
}

/* sendto hook */
#define sendto test_sendto
#include "../../lib/posix.c"
#undef sendto

static void readable(int fd) {
  struct pollfd p = {fd, POLLIN, 0};
  CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
}

static void exchange(int v6) {
  int relay = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  CHECK(relay >= 0);
  struct sockaddr_storage address = {0}, peer = {0};
  socklen_t len = v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
  if (v6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
    a->sin6_family = AF_INET6;
    a->sin6_addr = in6addr_loopback;
  } else {
    struct sockaddr_in *a = (struct sockaddr_in *)&address;
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  CHECK(bind(relay, (struct sockaddr *)&address, len) == 0);
  CHECK(getsockname(relay, (struct sockaddr *)&address, &len) == 0);
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, v6, v6, 0);
  c.ecn = 1;
  if (v6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
    memcpy(c.discovery.ip, &a->sin6_addr, 16);
    c.discovery.port = ntohs(a->sin6_port);
  } else {
    struct sockaddr_in *a = (struct sockaddr_in *)&address;
    memcpy(c.discovery.ip, &a->sin_addr, 4);
    c.discovery.port = ntohs(a->sin_port);
  }
  int outer_tos = 3;
  CHECK(setsockopt(relay, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_TCLASS : IP_TOS, &outer_tos, sizeof(outer_tos)) ==
        0);
  c.random_bytes = NULL;
  nanoamt_posix *io = nanoamt_posix_open(&c, 0);
  CHECK(io);
  nanoamt_packet packet;
  CHECK(nanoamt_posix_receive(io, 0, &packet) == NANOAMT_OK && packet.data == NULL);
  block_sends = 1;
  CHECK(nanoamt_posix_send(io, 0) == NANOAMT_OK);
  CHECK(nanoamt_posix_wants_write(io));
  CHECK(nanoamt_posix_next_timeout(io) == INT64_MAX);
  CHECK(!nanoamt_posix_is_joined(io));
  uint8_t queued[128];
  memcpy(queued, attempted, attempted_size);
  CHECK(nanoamt_posix_send(io, 0) == NANOAMT_OK);
  CHECK(attempted_size == 8 && !memcmp(queued, attempted, 8));
  block_sends = 0;
  CHECK(nanoamt_posix_send(io, 0) == NANOAMT_PACKET);
  CHECK(!nanoamt_posix_wants_write(io));
  readable(relay);
  nanoamt_datagram out;
  len = sizeof(peer);
  CHECK(recvfrom(relay, out.bytes, sizeof(out.bytes), 0, (struct sockaddr *)&peer, &len) == 8);
  CHECK(!memcmp(queued, out.bytes, 8));
  uint8_t p[128];
  size_t n = fixture_advertisement(p, &out, &c.discovery);
  CHECK(sendto(relay, p, n, 0, (struct sockaddr *)&peer, len) == (ssize_t)n);
  readable(nanoamt_posix_fd(io));
  CHECK(nanoamt_posix_receive(io, 1, &packet) == NANOAMT_OK);
  CHECK(nanoamt_posix_send(io, 1) == NANOAMT_PACKET);
  readable(relay);
  CHECK(recv(relay, out.bytes, sizeof(out.bytes), 0) == 8 && out.bytes[0] == 3);
  CHECK(out.bytes[1] == (v6 ? 3 : 2));
  n = fixture_dual_query(p, &out, &c, 125, 1);
  CHECK(sendto(relay, p, n, 0, (struct sockaddr *)&peer, len) == (ssize_t)n);
  readable(nanoamt_posix_fd(io));
  CHECK(nanoamt_posix_receive(io, 2, &packet) == NANOAMT_OK);
  block_sends = 1;
  CHECK(nanoamt_posix_send(io, 2) == NANOAMT_OK);
  CHECK(nanoamt_posix_wants_write(io));
  CHECK(!nanoamt_posix_is_joined(io));
  memcpy(queued, attempted, attempted_size);
  block_sends = 0;
  CHECK(nanoamt_posix_send(io, 2) == NANOAMT_PACKET);
  CHECK(!nanoamt_posix_wants_write(io));
  readable(relay);
  CHECK(recv(relay, out.bytes, sizeof(out.bytes), 0) == (v6 ? 104 : 56));
  CHECK(!memcmp(queued, out.bytes, v6 ? 104 : 56));
  CHECK(out.bytes[v6 ? 68 : 44] == 1);
  CHECK(nanoamt_posix_is_joined(io));
  CHECK(nanoamt_posix_get_state(io) == NANOAMT_STATE_JOINED);
  n = fixture_dual_data(p, &c, 1, 1);
  if (v6)
    p[3] |= 0x20;
  else {
    p[3] |= 2;
    ip_checksum(p + 2);
  }
  CHECK(sendto(relay, p, n, 0, (struct sockaddr *)&peer, len) == (ssize_t)n);
  readable(nanoamt_posix_fd(io));
  CHECK(nanoamt_posix_receive(io, 3, &packet) == NANOAMT_PACKET);
  CHECK(packet.size == 5 && packet.data[0] == 0x40 && packet.tos == 0x2f);
  int64_t now = nanoamt_posix_next_timeout(io);
  if (now < 4)
    now = 4;
  block_sends = 1;
  CHECK(nanoamt_posix_send(io, now) == NANOAMT_OK);
  CHECK(nanoamt_posix_wants_write(io));
  CHECK(nanoamt_posix_leave(io, now) == NANOAMT_OK);
  CHECK(!nanoamt_posix_wants_write(io));
  CHECK(!nanoamt_posix_is_joined(io));
  block_sends = 0;
  CHECK(nanoamt_posix_send(io, now) == NANOAMT_PACKET);
  readable(relay);
  CHECK(recv(relay, out.bytes, sizeof(out.bytes), 0) == 30 && out.bytes[0] == 7);
  nanoamt_posix_close(io);
  io = nanoamt_posix_open(&c, 0);
  CHECK(io);
  block_sends = 1;
  CHECK(nanoamt_posix_send(io, 0) == NANOAMT_OK);
  CHECK(nanoamt_posix_leave(io, 0) == NANOAMT_OK);
  CHECK(!nanoamt_posix_wants_write(io));
  block_sends = 0;
  CHECK(nanoamt_posix_send(io, 0) == NANOAMT_OK);
  CHECK(nanoamt_posix_get_state(io) == NANOAMT_STATE_CLOSED);
  nanoamt_posix_close(io);
  close(relay);
}

int main(void) {
  exchange(0);
  exchange(1);
  puts("posix: real UDP discovery, query, report, data and leave passed");
  return 0;
}
