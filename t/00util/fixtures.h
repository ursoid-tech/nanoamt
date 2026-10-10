#ifndef NANOAMT_TEST_FIXTURES_H
#define NANOAMT_TEST_FIXTURES_H
#include "nanoamt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                          \
      abort();                                                                                                         \
    }                                                                                                                  \
  } while (0)

static uint16_t sum16(const uint8_t *p, size_t n) {
  unsigned sum = 0;
  for (size_t i = 0; i < n; ++i)
    sum += (unsigned)p[i] << (i % 2 ? 0 : 8);
  while (sum > 65535)
    sum = (sum & 65535) + (sum >> 16);
  return (uint16_t)(65535 - sum);
}
static void put16(uint8_t *p, unsigned n) {
  p[0] = (uint8_t)(n >> 8);
  p[1] = (uint8_t)n;
}
static void ip_checksum(uint8_t *p) {
  p[10] = p[11] = 0;
  put16(p + 10, sum16(p, (p[0] & 15) * 4));
}
static int fixture_random(void *ctx, void *p, size_t n) {
  unsigned *counter = ctx;
  memset(p, (int)(++*counter & 255), n);
  return 0;
}
static nanoamt_config fixture_config(unsigned *counter) {
  nanoamt_config c = {0};
  c.discovery = (nanoamt_endpoint){{192, 0, 2, 1}, NANOAMT_PORT};
  const uint8_t source[] = {192, 0, 2, 10}, group[] = {232, 1, 2, 3};
  memcpy(c.source, source, 4);
  memcpy(c.group, group, 4);
  c.port = 5000;
  c.random_bytes = fixture_random;
  c.random_context = counter;
  return c;
}
static size_t fixture_advertisement(uint8_t *p, const nanoamt_datagram *discovery, const nanoamt_endpoint *relay) {
  size_t address_size = relay->ip_version == 6 ? 16 : 4;
  memset(p, 0, 8 + address_size);
  p[0] = 2;
  memcpy(p + 4, discovery->bytes + 4, 4);
  memcpy(p + 8, relay->ip, address_size);
  return 8 + address_size;
}

static size_t fixture_query(uint8_t *p, const nanoamt_datagram *request, uint8_t qqic, unsigned flags) {
  size_t size = 48 + ((flags & 1) ? 18 : 0);
  memset(p, 0, size);
  p[0] = 4;
  p[1] = (uint8_t)flags;
  memcpy(p + 2, "COOKIE", 6);
  memcpy(p + 8, request->bytes + 4, 4);
  uint8_t *ip = p + 12, *igmp = p + 36;
  ip[0] = 0x46;
  put16(ip + 2, 36);
  ip[8] = 1;
  ip[9] = 2;
  ip[12] = 192;
  ip[14] = 2;
  ip[15] = 1;
  ip[16] = 224;
  ip[19] = 1;
  ip[20] = 0x94;
  ip[21] = 4;
  ip_checksum(ip);
  igmp[0] = 0x11;
  igmp[1] = 100;
  igmp[8] = 2;
  igmp[9] = qqic;
  put16(igmp + 2, sum16(igmp, 12));
  if (flags & 1) {
    put16(p + 48, 40000);
    p[size - 1] = 7;
  }
  return size;
}
static size_t fixture_data(uint8_t *p, const nanoamt_config *c, int options, int checksum) {
  size_t header = options ? 24 : 20;
  memset(p, 0, 128);
  p[0] = 6;
  uint8_t *ip = p + 2, *udp = ip + header;
  ip[0] = (uint8_t)(0x40 | (header / 4));
  ip[1] = 0x2c;
  put16(ip + 2, (unsigned)header + 13);
  ip[8] = 42;
  ip[9] = 17;
  memcpy(ip + 12, c->source, 4);
  memcpy(ip + 16, c->group, 4);
  if (options) {
    ip[20] = 0x94;
    ip[21] = 4;
  }
  ip_checksum(ip);
  put16(udp, 1234);
  put16(udp + 2, c->port);
  put16(udp + 4, 13);
  memcpy(udp + 8, "\x40\x00\x80\xff\x01", 5);
  if (checksum) {
    uint8_t pseudo[25];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = 17;
    put16(pseudo + 10, 13);
    memcpy(pseudo + 12, udp, 13);
    uint16_t sum = sum16(pseudo, sizeof(pseudo));
    put16(udp + 6, sum ? sum : 65535);
  }
  return 2 + header + 13;
}
static void fixture_checksum6(uint8_t *ip, uint8_t *payload, size_t length, unsigned protocol, size_t at) {
  uint8_t buffer[2048] = {0};
  CHECK(length + 40 <= sizeof(buffer));
  payload[at] = payload[at + 1] = 0;
  memcpy(buffer, ip + 8, 32);
  put16(buffer + 34, (unsigned)length);
  buffer[39] = (uint8_t)protocol;
  memcpy(buffer + 40, payload, length);
  put16(payload + at, sum16(buffer, 40 + length));
}

static nanoamt_config fixture_dual_config(unsigned *counter, int outer6, int inner6, int any_source) {
  nanoamt_config c = fixture_config(counter);
  if (outer6) {
    memset(c.discovery.ip, 0, 16);
    c.discovery.ip_version = 6;
    c.discovery.ip[0] = 0x20;
    c.discovery.ip[1] = 1;
    c.discovery.ip[2] = 0x0d;
    c.discovery.ip[3] = 0xb8;
    c.discovery.ip[15] = 1;
  }
  c.any_source = (uint8_t)any_source;
  if (inner6) {
    c.ip_version = 6;
    memset(c.source, 0, 16);
    memset(c.group, 0, 16);
    c.source[0] = 0x20;
    c.source[1] = 1;
    c.source[2] = 0x0d;
    c.source[3] = 0xb8;
    c.source[15] = 10;
    c.group[0] = 255;
    c.group[1] = any_source ? 0x1e : 0x3e;
    c.group[14] = 0x12;
    c.group[15] = 0x34;
  } else if (any_source)
    c.group[0] = 239;
  return c;
}

static size_t fixture_dual_query(uint8_t *p, const nanoamt_datagram *request, const nanoamt_config *c, uint8_t qqic,
                                 unsigned flags) {
  if (c->ip_version != 6)
    return fixture_query(p, request, qqic, flags);
  size_t size = 88 + ((flags & 1) ? 18 : 0);
  memset(p, 0, size);
  p[0] = 4;
  p[1] = (uint8_t)flags;
  memcpy(p + 2, "COOKIE", 6);
  memcpy(p + 8, request->bytes + 4, 4);
  uint8_t *ip = p + 12, *mld = ip + 48;
  ip[0] = 0x60;
  ip[5] = 36;
  ip[7] = 1;
  memcpy(ip + 8, c->source, 16);
  ip[24] = 255;
  ip[25] = 2;
  ip[39] = 1;
  memcpy(ip + 40, (uint8_t[]){58, 0, 5, 2, 0, 0, 1, 0}, 8);
  mld[0] = 130;
  mld[5] = 100;
  mld[24] = 2;
  mld[25] = qqic;
  fixture_checksum6(ip, mld, 28, 58, 2);
  if (flags & 1) {
    put16(p + 88, 40000);
    p[size - 1] = 7;
  }
  return size;
}

static size_t fixture_dual_data(uint8_t *p, const nanoamt_config *c, int options, int checksum) {
  if (c->ip_version != 6)
    return fixture_data(p, c, options, checksum);
  memset(p, 0, 128);
  p[0] = 6;
  uint8_t *ip = p + 2, *udp = ip + 40 + (options ? 8 : 0);
  ip[0] = 0x62;
  ip[1] = 0xc0;
  ip[7] = 42;
  put16(ip + 4, (unsigned)(udp - ip - 40) + 13);
  ip[6] = options ? 0 : 17;
  if (options)
    memcpy(ip + 40, (uint8_t[]){17, 0, 5, 2, 0, 0, 1, 0}, 8);
  memcpy(ip + 8, c->source, 16);
  memcpy(ip + 24, c->group, 16);
  put16(udp, 1234);
  put16(udp + 2, c->port);
  put16(udp + 4, 13);
  memcpy(udp + 8, "\x40\x00\x80\xff\x01", 5);
  if (checksum)
    fixture_checksum6(ip, udp, 13, 17, 6);
  return (size_t)(udp - p) + 13;
}
#endif
