#ifndef NANOAMT_AMTQ_H
#define NANOAMT_AMTQ_H

#include "nanoamt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NANOAMTQ_ALPN "amtq-00"
#define NANOAMTQ_MAX_CONTROL_VALUE 65587U
#define NANOAMTQ_MAX_DATA_MESSAGE 65577U
#define NANOAMTQ_MAX_MEMBERSHIPS 64U
#define NANOAMTQ_MAX_CONTEXTS 64U
#define NANOAMTQ_CONTROL_CAPACITY 8192U

enum {
  NANOAMTQ_OK = 0,
  NANOAMTQ_PACKET = 1,
  NANOAMTQ_IGNORED = 2,
  NANOAMTQ_INCOMPLETE = 3,
  NANOAMTQ_MEMBERSHIP = 4,
  NANOAMTQ_ERROR_ARGUMENT = -1,
  NANOAMTQ_ERROR_BUFFER = -2,
  NANOAMTQ_ERROR_PROTOCOL = -3,
  NANOAMTQ_ERROR_RANDOM = -4,
  NANOAMTQ_ERROR_TIMEOUT = -5,
  NANOAMTQ_ERROR_MEMORY = -6,
  NANOAMTQ_ERROR_LIMIT = -7,
  NANOAMTQ_ERROR_POLICY = -8,
  NANOAMTQ_ERROR_STALE = -9
};
enum {
  NANOAMTQ_CLOSE_PROTOCOL = 0x100,
  NANOAMTQ_CLOSE_INTERNAL = 0x101,
  NANOAMTQ_CLOSE_CONTROL_STREAM = 0x102,
  NANOAMTQ_CLOSE_SETTINGS = 0x103,
  NANOAMTQ_CLOSE_AMT_MESSAGE = 0x104,
  NANOAMTQ_CLOSE_CONTEXT = 0x105,
  NANOAMTQ_CLOSE_EXCESSIVE_LOAD = 0x106
};
enum {
  NANOAMTQ_SETTINGS = 0,
  NANOAMTQ_AMT_CONTROL = 1,
  NANOAMTQ_CONTEXT = 2,
  NANOAMTQ_CONTEXT_CLOSE = 3,
  NANOAMTQ_CONTEXT_ACK = 4
};
enum { NANOAMTQ_COMPLETE = 0, NANOAMTQ_FRAGMENT = 1 };

typedef struct nanoamtq_record {
  uint64_t type;
  const uint8_t *data;
  size_t size;
} nanoamtq_record;
typedef struct nanoamtq_datagram {
  uint64_t format, context_id, packet_id;
  size_t total_size, offset;
  const uint8_t *data;
  size_t size;
} nanoamtq_datagram;
int nanoamtq_record_decode(const uint8_t *bytes, size_t size, nanoamtq_record *record, size_t *consumed);
int nanoamtq_record_encode(const nanoamtq_record *record, uint8_t *bytes, size_t capacity, size_t *size);
int nanoamtq_datagram_decode(const uint8_t *bytes, size_t size, nanoamtq_datagram *datagram);
int nanoamtq_datagram_encode(const nanoamtq_datagram *datagram, uint8_t *bytes, size_t capacity, size_t *size);

typedef struct nanoamtq nanoamtq;
typedef struct nanoamtq_config {
  uint8_t ip_version; /* 0/4: IPv4, 6: IPv6 */
  int (*random_bytes)(void *context, void *bytes, size_t size);
  void *random_context;
  unsigned max_incomplete;
  unsigned max_fragment_ranges;
  uint32_t reassembly_timeout_ms;
  uint32_t control_timeout_ms;
  uint32_t refresh_cap_ms;
} nanoamtq_config;
typedef struct nanoamtq_membership {
  uint8_t source[16], group[16];
  uint8_t any_source; /* ASM mode */
  uint16_t port;      /* local UDP port, 0: all */
} nanoamtq_membership;
typedef struct nanoamtq_control {
  size_t size;
  uint8_t bytes[NANOAMTQ_CONTROL_CAPACITY];
} nanoamtq_control;

nanoamtq *nanoamtq_new(const nanoamtq_config *config, int64_t now_ms);
void nanoamtq_free(nanoamtq *gateway);
int nanoamtq_set_memberships(nanoamtq *gateway, const nanoamtq_membership *memberships, size_t count);
int nanoamtq_send(nanoamtq *gateway, int64_t now_ms, nanoamtq_control *output);
int nanoamtq_receive_control(nanoamtq *gateway, int64_t now_ms, uint64_t stream_id, const uint8_t *bytes, size_t size,
                             int fin);
int nanoamtq_receive_datagram(nanoamtq *gateway, int64_t now_ms, const uint8_t *bytes, size_t size,
                              nanoamt_packet *packet);
int64_t nanoamtq_next_timeout(const nanoamtq *gateway);
int nanoamtq_is_ready(const nanoamtq *gateway);
int nanoamtq_error(const nanoamtq *gateway);
uint64_t nanoamtq_close_error(const nanoamtq *gateway);

#ifdef __cplusplus
}
#endif
#endif
