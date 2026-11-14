#ifndef NANOAMT_RELAY_H
#define NANOAMT_RELAY_H

#include "nanoamt/membership.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nanoamt_relay nanoamt_relay;
typedef struct nanoamt_relay_config {
  nanoamt_endpoint advertised4, advertised6; /* zero IP: use received local address */
  uint8_t query_source4[16], query_source6[16];
  unsigned max_clients;        /* 0: 64; maximum 1024 */
  unsigned max_clients_per_ip; /* 0: 16 */
  unsigned max_fanout_entries; /* 0: 65536; maximum 1048576 canonical subscriber keys */
  nanoamt_membership_config memberships, aggregate;
  uint32_t query_interval_ms;  /* 0: 125000; rounded up to wire QQIC */
  uint32_t query_response_ms;  /* 0: 10000 */
  unsigned robustness;         /* 0: 2; maximum 7 */
  uint32_t secret_interval_ms; /* 0: 7200000 */
  uint32_t path_mtu;           /* outer IP MTU, 0: 1500; maximum 65535 */
  uint32_t minimum_path_mtu;   /* 0: 576 (IPv6 always at least 1280) */
  int (*random_bytes)(void *context, void *bytes, size_t size);
  void *random_context;
  /* keyed hash truncated to 6 bytes; key and input are borrowed for the call */
  int (*response_mac)(void *context, const uint8_t key[32], const uint8_t *input, size_t size, uint8_t mac[6]);
  void *mac_context;
  /* install proposed aggregate upstream state before returning zero; failure
   * preserves prior subscriptions; NULL accepts all state; no reentry */
  int (*authorize)(void *context, const nanoamt_endpoint *peer, const nanoamt_memberships *requested,
                   const nanoamt_memberships *aggregate);
  void *authorize_context;
  /* workaround for Linux AMT gateway quirks; 0: RFC wire, 4/6: accept both
   * legacy (0x80) and RFC (0x01) P bits and omit optional query trailer */
  unsigned linux_gateway_family;
} nanoamt_relay_config;

typedef struct nanoamt_relay_control {
  nanoamt_endpoint source, destination;
  size_t size;
  uint8_t bytes[NANOAMT_CONTROL_CAPACITY];
} nanoamt_relay_control;
enum { NANOAMT_RELAY_DATA = 0, NANOAMT_RELAY_MTU_FEEDBACK = 1 };
typedef struct nanoamt_relay_output {
  nanoamt_endpoint source, destination;
  uint64_t tunnel_id;
  uint16_t client_slot; /* private validation hint; tunnel_id and endpoints are still checked */
  size_t size;
  uint32_t mtu; /* FEEDBACK: inner MTU, destination is the multicast source */
  uint8_t kind, tos, dont_fragment;
} nanoamt_relay_output;
/* caller-owned fanout cursor; input packet must stay immutable and alive until
 * next returns OK; reset/drop cursor to discard remaining fanout */
typedef struct nanoamt_relay_forward {
  const nanoamt_relay *owner;
  const uint8_t *ip;
  size_t size, client, offset;
  uint64_t max_tunnel_id;
  uint8_t eligible[128];
  uint8_t feedback_done;
} nanoamt_relay_forward;
typedef struct nanoamt_relay_stats {
  /* data_packets and data_bytes count core outputs emitted before socket send */
  uint64_t discoveries, requests, updates, teardowns, bad_mac, malformed;
  uint64_t limited, denied, expired, data_packets, data_bytes, mtu_drops;
  size_t clients, fanout_entries;
  uint64_t fanout_candidates, fanout_rebuilds, timer_scans;
} nanoamt_relay_stats;

nanoamt_relay *nanoamt_relay_new(const nanoamt_relay_config *config, int64_t now_ms);
void nanoamt_relay_free(nanoamt_relay *relay);
int nanoamt_relay_tick(nanoamt_relay *relay, int64_t now_ms);
int64_t nanoamt_relay_next_timeout(const nanoamt_relay *relay);
/* returned control packet commits its generation; retain across socket EAGAIN */
int nanoamt_relay_receive(nanoamt_relay *relay, int64_t now_ms, const nanoamt_endpoint *peer,
                          const nanoamt_endpoint *local, const uint8_t *bytes, size_t size,
                          nanoamt_relay_control *output);
int nanoamt_relay_snapshot(nanoamt_relay *relay, int64_t now_ms, nanoamt_memberships **output);
int nanoamt_relay_set_path_mtu(nanoamt_relay *relay, int64_t now_ms, const nanoamt_endpoint *peer,
                               const nanoamt_endpoint *local, uint32_t mtu);
int nanoamt_relay_forward_begin(nanoamt_relay *relay, int64_t now_ms, const uint8_t *ip, size_t size,
                                nanoamt_relay_forward *cursor);
/* buffer errors do not advance cursor; PACKET consumes one output, revalidate
 * with output_valid before deferred send; FEEDBACK quotes original IP packet */
int nanoamt_relay_forward_next(nanoamt_relay *relay, int64_t now_ms, nanoamt_relay_forward *cursor, uint8_t *bytes,
                               size_t capacity, nanoamt_relay_output *output);
int nanoamt_relay_output_valid(nanoamt_relay *relay, int64_t now_ms, const nanoamt_relay_output *output,
                               const uint8_t *bytes, size_t size);
void nanoamt_relay_get_stats(const nanoamt_relay *relay, nanoamt_relay_stats *output);

#ifdef __cplusplus
}
#endif
#endif
