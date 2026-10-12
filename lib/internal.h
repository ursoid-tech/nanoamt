#ifndef NANOAMT_INTERNAL_H
#define NANOAMT_INTERNAL_H

#include "nanoamt.h"
#include <string.h>

enum message_type {
  RELAY_DISCOVERY = 1,
  RELAY_ADVERTISEMENT = 2,
  RELAY_REQUEST = 3,
  MEMBERSHIP_QUERY = 4,
  MEMBERSHIP_UPDATE = 5,
  MULTICAST_DATA = 6,
  TEARDOWN = 7
};

typedef struct ip_packet {
  uint8_t *payload, *source, *destination;
  size_t size, payload_size;
  uint8_t version, protocol, ttl, tos;
  int router_alert;
} ip_packet;

typedef struct nanoamt_reassembly nanoamt_reassembly;
nanoamt_reassembly *nanoamt_reassembly_create(void);
void nanoamt_reassembly_destroy(nanoamt_reassembly *r);
int nanoamt_reassemble(nanoamt_reassembly *r, int64_t now, uint8_t **bytes, size_t *size);

static inline unsigned ip_version(unsigned version) {
  return version ? version : 4;
}
static inline size_t ip_address_size(unsigned version) {
  return version == 6 ? 16 : 4;
}
static inline int zero(const uint8_t *p, size_t n) {
  uint8_t v = 0;
  while (n--)
    v |= *p++;
  return v == 0;
}

static inline uint16_t read16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static inline void write16(uint8_t *p, uint16_t n) {
  p[0] = (uint8_t)(n >> 8);
  p[1] = (uint8_t)n;
}
static inline int endpoint_equal(const nanoamt_endpoint *a, const nanoamt_endpoint *b) {
  return ip_version(a->ip_version) == ip_version(b->ip_version) && a->port == b->port &&
         (ip_version(a->ip_version) != 6 || a->scope_id == b->scope_id) &&
         memcmp(a->ip, b->ip, ip_address_size(a->ip_version)) == 0;
}
static inline int unicast(const uint8_t *p) {
  return p[0] != 0 && p[0] < 224;
}
static inline int address_unicast(const uint8_t *p, unsigned version) {
  return ip_version(version) == 4 ? unicast(p) : p[0] != 255 && !zero(p, 16);
}
static inline int multicast(const uint8_t *p, unsigned version) {
  return ip_version(version) == 4 ? (p[0] & 240) == 224 : p[0] == 255;
}

uint16_t nanoamt_checksum(const uint8_t *bytes, size_t size, uint32_t sum);
int nanoamt_ecn_decapsulate(uint8_t *bytes, size_t size, unsigned outer);
void nanoamt_ecn_set(uint8_t *bytes, unsigned ecn);
int nanoamt_ip_decode(uint8_t *bytes, size_t size, ip_packet *ip);
int nanoamt_ip_forward_decode(const uint8_t *bytes, size_t size, ip_packet *ip);
size_t nanoamt_general_query(uint8_t *ip, unsigned version, const uint8_t *source, uint8_t qqic, unsigned robustness,
                             uint32_t response_ms);
uint32_t nanoamt_pseudo_sum(const ip_packet *ip, uint8_t protocol, size_t size);
int nanoamt_query_decode(uint8_t *bytes, size_t size, unsigned version, uint32_t *interval_ms, unsigned *robustness);
int nanoamt_udp_decode(uint8_t *bytes, size_t size, const nanoamt_config *config, nanoamt_packet *packet);
enum report_type { REPORT_CURRENT, REPORT_JOIN, REPORT_LEAVE };
void nanoamt_report_encode(nanoamt_datagram *out, const nanoamt_config *config, const uint8_t mac[6],
                           const uint8_t nonce[4], enum report_type type);

#endif
