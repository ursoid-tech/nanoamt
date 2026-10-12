#ifndef NANOAMT_NATIVE_H
#define NANOAMT_NATIVE_H

#include "nanoamt/membership.h"
#include "nanoamt/posix.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nanoamt_native nanoamt_native;
typedef struct nanoamt_native_config {
  uint32_t interface_index; /* required; use the actual VLAN interface if applicable */
  unsigned max_groups;      /* 0: 1024, maximum 4096 */
  unsigned max_sources;     /* 0: 4096, maximum 65536 across all groups */
  unsigned feedback_rate;   /* 0: 10 ICMP messages/sec */
  unsigned feedback_burst;  /* 0: 10 */
} nanoamt_native_config;
typedef struct nanoamt_native_packet {
  uint8_t *ip; /* borrowed until the next receive or close */
  size_t size;
  uint32_t interface_index;
  uint8_t outgoing;
} nanoamt_native_packet;
typedef struct nanoamt_native_stats {
  uint64_t captured, filtered, truncated, malformed, offload_fixed, offload_dropped;
  uint64_t transactions, failed_transactions, feedback_sent, feedback_errors, feedback_limited;
  size_t groups, sources;
} nanoamt_native_stats;

/* Linux only; AF_PACKET needs CAP_NET_RAW. Single-threaded, nonblocking.
 * Each group has its own RFC 3678 subscription socket. Kernel filter limits
 * may reject a transaction even within configured bounds. No partial grant. */
nanoamt_native *nanoamt_native_open(const nanoamt_native_config *config);
void nanoamt_native_close(nanoamt_native *native);
int nanoamt_native_fd(const nanoamt_native *native);
/* Allocate/prepare before replacing subscriptions. Failure preserves prior
 * joins and capture policy. After relay expiry/withdrawal, reconcile the new
 * aggregate snapshot too, to prune native interest. Snapshot is copied. */
int nanoamt_native_reconcile(nanoamt_native *native, const nanoamt_memberships *aggregate);
int nanoamt_native_authorize(void *context, const nanoamt_endpoint *peer, const nanoamt_memberships *requested,
                             const nanoamt_memberships *aggregate);
int nanoamt_native_receive(nanoamt_native *native, nanoamt_native_packet *packet);
/* Suitable for relay_posix_config.mtu_feedback. Quote is borrowed; raw ICMP
 * sockets open lazily. Feedback is globally rate-limited with caller time. */
void nanoamt_native_mtu_feedback(void *context, int64_t now_ms, const uint8_t *ip, size_t size, uint32_t mtu);
void nanoamt_native_get_stats(const nanoamt_native *native, nanoamt_native_stats *stats);

#ifdef __cplusplus
}
#endif
#endif
