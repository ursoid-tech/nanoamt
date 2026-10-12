#ifndef NANOAMT_RELAY_POSIX_H
#define NANOAMT_RELAY_POSIX_H

#include "nanoamt/relay.h"
#include "nanoamt/posix.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nanoamt_relay_posix nanoamt_relay_posix;
typedef struct nanoamt_relay_posix_config {
  nanoamt_endpoint listen; /* wildcard allowed; port 0 requests an ephemeral port */
  nanoamt_relay_config relay;
  unsigned control_capacity; /* 0: 32, maximum 1024 */
  unsigned input_capacity;   /* 0: 8, maximum 1024 */
  size_t input_bytes;        /* 0: 1 MiB, includes retained fanout input */
  uint32_t data_age_ms;      /* 0: 1000 */
  uint32_t control_age_ms;   /* 0: 5000 */
  unsigned send_budget;      /* 0: 64 outputs per call, maximum 4096 */
  unsigned control_rate;     /* 0: 1000 packets/sec, before protocol parsing */
  unsigned control_burst;    /* 0: 256 */
  unsigned source_rate;      /* 0: 100 packets/sec per source IP */
  unsigned source_burst;     /* 0: 32; source table has 64 bounded LRU slots */
  /* Called synchronously for a core MTU event; quote is borrowed. The provider
   * emits/rate-limits native ICMP. No callback means feedback is counted only. */
  void (*mtu_feedback)(void *context, int64_t now_ms, const uint8_t *ip, size_t size, uint32_t mtu);
  void *feedback_context;
} nanoamt_relay_posix_config;
typedef struct nanoamt_relay_posix_stats {
  uint64_t received, truncated, rate_limited, control_dropped, input_dropped;
  uint64_t sent, send_errors, expired, revoked, mtu_feedback;
  size_t queued_controls, queued_inputs, retained_input_bytes;
} nanoamt_relay_posix_stats;

/* Linux packet-info support is required; unsupported platforms return ENOTSUP.
 * Single-threaded, caller-clocked. relay.response_mac is mandatory; missing
 * random_bytes uses /dev/urandom. Queues own copies, never caller storage. */
nanoamt_relay_posix *nanoamt_relay_posix_open(const nanoamt_relay_posix_config *config, int64_t now_ms);
void nanoamt_relay_posix_close(nanoamt_relay_posix *io);
int nanoamt_relay_posix_fd(const nanoamt_relay_posix *io);
void nanoamt_relay_posix_bound(const nanoamt_relay_posix *io, nanoamt_endpoint *endpoint);
nanoamt_relay *nanoamt_relay_posix_core(nanoamt_relay_posix *io);         /* borrowed; no callback reentry */
int nanoamt_relay_posix_receive(nanoamt_relay_posix *io, int64_t now_ms); /* one control datagram */
int nanoamt_relay_posix_forward(nanoamt_relay_posix *io, int64_t now_ms, const uint8_t *ip, size_t size);
int nanoamt_relay_posix_send(nanoamt_relay_posix *io, int64_t now_ms);
int nanoamt_relay_posix_wants_write(const nanoamt_relay_posix *io);
int64_t nanoamt_relay_posix_next_timeout(const nanoamt_relay_posix *io);
void nanoamt_relay_posix_get_stats(const nanoamt_relay_posix *io, nanoamt_relay_posix_stats *stats);

#ifdef __cplusplus
}
#endif
#endif
