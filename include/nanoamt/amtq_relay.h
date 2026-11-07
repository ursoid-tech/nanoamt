#ifndef NANOAMT_AMTQ_RELAY_H
#define NANOAMT_AMTQ_RELAY_H

#include "nanoamt/amtq.h"
#include "nanoamt/membership.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nanoamtq_relay nanoamtq_relay;
typedef struct nanoamtq_authorization nanoamtq_authorization;
typedef struct nanoamtq_relay_config {
  uint64_t connection_id;        /* required nonzero, process-unique stable handle */
  uint64_t peer_max_uni_streams; /* peer QUIC receive stream credit */
  nanoamt_membership_config memberships;
  uint8_t query_source4[16], query_source6[16];
  unsigned max_contexts;       /* 0: 64, configurable downward */
  uint32_t control_timeout_ms; /* 0: 10000; also bounds authorization waits */
  uint32_t query_interval_ms;  /* 0: 125000; rounded up to wire QQIC */
  uint32_t query_response_ms;  /* 0: 10000 */
  unsigned data_modes;         /* 0/1: datagram, 3: datagram and reliable block */
  unsigned robustness;         /* 0: 2, maximum 7 */
} nanoamtq_relay_config;

/* single-threaded protocol object for one authenticated amtq-00 connection;
 * monotonic nonnegative clock in milliseconds below INT64_MAX */
nanoamtq_relay *nanoamtq_relay_new(const nanoamtq_relay_config *config, int64_t now_ms);
void nanoamtq_relay_free(nanoamtq_relay *relay);
int nanoamtq_relay_tick(nanoamtq_relay *relay, int64_t now_ms);
int64_t nanoamtq_relay_next_timeout(const nanoamtq_relay *relay);
int nanoamtq_relay_error(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_close_error(const nanoamtq_relay *relay);
/* SETTINGS and an acknowledged active context */
int nanoamtq_relay_is_ready(const nanoamtq_relay *relay);

/* incremental stream 0 input; MEMBERSHIP pauses after an update, retain suffix
 * after *consumed and resume after authorization commits; fin=1 on FIN/RESET */
int nanoamtq_relay_receive_control(nanoamtq_relay *relay, int64_t now_ms, uint64_t stream_id, const uint8_t *bytes,
                                   size_t size, int fin, size_t *consumed);
int nanoamtq_relay_receive_datagram(nanoamtq_relay *relay, int64_t now_ms, const uint8_t *bytes, size_t size);
/* returning a record commits local state; retain until QUIC accepts it */
int nanoamtq_relay_send(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_control *output);

/* borrowed views valid until commit/free; requested returns proposed state
 * while paused, otherwise last committed state */
const nanoamt_memberships *nanoamtq_relay_requested(const nanoamtq_relay *relay);
const nanoamt_memberships *nanoamtq_relay_authorized(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_generation(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_authorization_revision(const nanoamtq_relay *relay);
int nanoamtq_relay_pending(const nanoamtq_relay *relay);
/* prepare bounded subset of requested state before installing native joins;
 * commit performs no allocations; caller frees token after either outcome */
int nanoamtq_relay_prepare_authorization(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation,
                                         const nanoamt_memberships *authorized, nanoamtq_authorization **token);
int nanoamtq_relay_commit_authorization(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_authorization *token);
void nanoamtq_relay_authorization_free(nanoamtq_authorization *token);
/* convenience policies for direct packet injection or synchronous adapters */
int nanoamtq_relay_authorize_all(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation);
int nanoamtq_relay_deny(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation);

/* context 0 opens first, IDs increase without reuse; close revokes queued data */
int nanoamtq_relay_open_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);
int nanoamtq_relay_open_context_mode(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, unsigned mode);
int nanoamtq_relay_context_mode(const nanoamtq_relay *relay, uint64_t context_id);
int nanoamtq_relay_preferred_mode(const nanoamtq_relay *relay);
int nanoamtq_relay_close_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);
/* release reliably closed context only after QUIC retires all its streams */
int nanoamtq_relay_release_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);

typedef struct nanoamtq_relay_cursor {
  const nanoamtq_relay *owner;
  const uint8_t *ip;
  size_t size, offset;
  uint64_t context_id, packet_id;
} nanoamtq_relay_cursor;
typedef struct nanoamtq_relay_datagram_output {
  uint64_t connection_id, context_id, packet_id; /* packet_id is block ID for reliable records */
  size_t size, offset, total_size;
  uint8_t format, ip_version, source[16], group[16];
} nanoamtq_relay_datagram_output;
/* immutable IP input stays alive until cursor finishes or is discarded;
 * max_payload is current writable QUIC DATAGRAM budget including AMTQ header */
int nanoamtq_relay_datagram_begin(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, const uint8_t *ip,
                                  size_t size, nanoamtq_relay_cursor *cursor);
int nanoamtq_relay_datagram_next(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_relay_cursor *cursor,
                                 size_t max_payload, uint8_t *bytes, size_t capacity,
                                 nanoamtq_relay_datagram_output *output);
/* retain metadata with blocked output and revalidate before deferred send */
int nanoamtq_relay_datagram_valid(nanoamtq_relay *relay, int64_t now_ms, const nanoamtq_relay_datagram_output *output,
                                  const uint8_t *bytes, size_t size);

/* reliable blocks use server-initiated uni streams; begin emits stream header,
 * record emits one length-prefixed AMT data message; finish follows FIN */
int nanoamtq_relay_reliable_begin(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, uint64_t *block_id,
                                  uint8_t *bytes, size_t capacity, size_t *size);
int nanoamtq_relay_reliable_record(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, uint64_t block_id,
                                   const uint8_t *ip, size_t size, uint8_t *bytes, size_t capacity,
                                   nanoamtq_relay_datagram_output *output);
int nanoamtq_relay_reliable_valid(nanoamtq_relay *relay, int64_t now_ms, const nanoamtq_relay_datagram_output *output,
                                  const uint8_t *bytes, size_t size);
int nanoamtq_relay_reliable_finish(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, uint64_t block_id);
int nanoamtq_relay_reliable_abort(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, uint64_t block_id);

#ifdef __cplusplus
}
#endif
#endif
