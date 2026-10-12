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
  uint64_t connection_id;        /* Required nonzero, process-unique stable handle. */
  uint64_t peer_max_uni_streams; /* Peer QUIC receive stream credit. */
  nanoamt_membership_config memberships;
  uint8_t query_source4[16], query_source6[16];
  unsigned max_contexts;       /* 0: 64, configurable downward */
  uint32_t control_timeout_ms; /* 0: 10000; also bounds authorization waits */
  uint32_t query_interval_ms;  /* 0: 125000; rounded up to wire QQIC */
  uint32_t query_response_ms;  /* 0: 10000 */
  unsigned data_modes;         /* 0/1: Datagram; 3: Datagram and Reliable Block. */
  unsigned robustness;         /* 0: 2, maximum 7 */
} nanoamtq_relay_config;

/* A single-threaded protocol object for one authenticated amtq-00 connection.
 * QUIC/TLS, native joins, admission policy and queues belong to the adapter.
 * The clock is monotonic, nonnegative milliseconds below INT64_MAX.
 */
nanoamtq_relay *nanoamtq_relay_new(const nanoamtq_relay_config *config, int64_t now_ms);
void nanoamtq_relay_free(nanoamtq_relay *relay);
int nanoamtq_relay_tick(nanoamtq_relay *relay, int64_t now_ms);
int64_t nanoamtq_relay_next_timeout(const nanoamtq_relay *relay);
int nanoamtq_relay_error(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_close_error(const nanoamtq_relay *relay);
/* SETTINGS and an acknowledged active context, independent of authorization
 * or end-to-end data reachability. */
int nanoamtq_relay_is_ready(const nanoamtq_relay *relay);

/* Incremental Stream 0 input. MEMBERSHIP pauses exactly after an Update;
 * retain the suffix after *consumed and resume after authorization commits.
 * Calls while paused consume zero bytes. FIN/RESET/STOP_SENDING use fin=1;
 * any nonzero stream ID or gateway DATAGRAM is a fatal role violation.
 */
int nanoamtq_relay_receive_control(nanoamtq_relay *relay, int64_t now_ms, uint64_t stream_id, const uint8_t *bytes,
                                   size_t size, int fin, size_t *consumed);
int nanoamtq_relay_receive_datagram(nanoamtq_relay *relay, int64_t now_ms, const uint8_t *bytes, size_t size);
/* Returning a record commits its local state. Retain the entire record and
 * its partial-write offset until QUIC accepts it; do not request another
 * record before acceptance or intentional connection closure. */
int nanoamtq_relay_send(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_control *output);

/* Borrowed views remain valid until commit/free. requested returns the
 * proposed state while paused, otherwise the last committed state.
 * A valid withdrawal gates data immediately, before a native join completes.
 */
const nanoamt_memberships *nanoamtq_relay_requested(const nanoamtq_relay *relay);
const nanoamt_memberships *nanoamtq_relay_authorized(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_generation(const nanoamtq_relay *relay);
uint64_t nanoamtq_relay_authorization_revision(const nanoamtq_relay *relay);
int nanoamtq_relay_pending(const nanoamtq_relay *relay);
/* Prepare a bounded subset of requested state BEFORE installing native joins.
 * Commit has no allocations. Tokens bind connection, request generation and
 * authorization revision, so stale results cannot grant traffic. On failed
 * commit, the adapter rolls back its native transaction. Caller frees a token
 * after either outcome; a successful commit empties it. Tokens/queued output
 * must never be reused for a newly created connection.
 */
int nanoamtq_relay_prepare_authorization(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation,
                                         const nanoamt_memberships *authorized, nanoamtq_authorization **token);
int nanoamtq_relay_commit_authorization(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_authorization *token);
void nanoamtq_relay_authorization_free(nanoamtq_authorization *token);
/* Convenience policies for direct packet injection or a synchronous adapter.
 * deny retains previous-authorized intersect requested; representation limits
 * may conservatively deny all state. No authorization acknowledgment exists.
 */
int nanoamtq_relay_authorize_all(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation);
int nanoamtq_relay_deny(nanoamtq_relay *relay, int64_t now_ms, uint64_t generation);

/* Context 0 must open first, IDs
 * subsequently increase without reuse. Data waits for ACK. Closing an active
 * context revokes queued data immediately and queues CONTEXT_CLOSE. */
int nanoamtq_relay_open_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);
int nanoamtq_relay_open_context_mode(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, unsigned mode);
int nanoamtq_relay_context_mode(const nanoamtq_relay *relay, uint64_t context_id);
int nanoamtq_relay_preferred_mode(const nanoamtq_relay *relay);
int nanoamtq_relay_close_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);
/* Release a reliably closed context only after QUIC has retired all its streams.
 * Until release, issued records remain valid for retransmission while authorized.
 * Returns ERROR_ARGUMENT for active, closing (not yet emitted), or unknown IDs. */
int nanoamtq_relay_release_context(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id);

typedef struct nanoamtq_relay_cursor {
  const nanoamtq_relay *owner;
  const uint8_t *ip;
  size_t size, offset;
  uint64_t context_id, packet_id;
} nanoamtq_relay_cursor;
typedef struct nanoamtq_relay_datagram_output {
  uint64_t connection_id, context_id, packet_id; /* packet_id is Block ID for reliable records. */
  size_t size, offset, total_size;
  uint8_t format, ip_version, source[16], group[16];
} nanoamtq_relay_datagram_output;
/* Immutable IP input stays alive until the cursor finishes or is discarded;
 * a cursor cannot outlive its relay. No packet storage is allocated by the
 * sender. max_payload is QUIC's CURRENT writable DATAGRAM application budget,
 * including AMTQ framing, not the advertised transport parameter or IP MTU.
 * Buffer errors neither advance the cursor nor consume a Packet ID.
 */
int nanoamtq_relay_datagram_begin(nanoamtq_relay *relay, int64_t now_ms, uint64_t context_id, const uint8_t *ip,
                                  size_t size, nanoamtq_relay_cursor *cursor);
int nanoamtq_relay_datagram_next(nanoamtq_relay *relay, int64_t now_ms, nanoamtq_relay_cursor *cursor,
                                 size_t max_payload, uint8_t *bytes, size_t capacity,
                                 nanoamtq_relay_datagram_output *output);
/* Retain metadata with blocked output; validate before deferred submission.
 * Withdrawals, policy changes, context closure and connection failure revoke
 * both complete messages and fragments already framed by next(). */
int nanoamtq_relay_datagram_valid(nanoamtq_relay *relay, int64_t now_ms, const nanoamtq_relay_datagram_output *output,
                                  const uint8_t *bytes, size_t size);

/* Reliable blocks use server-initiated unidirectional streams. Begin emits the
 * stream header, record emits one length-prefixed AMT Data message. Hold each
 * encoded buffer through partial QUIC writes and revalidate before submission.
 * Finish follows acceptance of a FIN after at least one complete record. Close
 * refuses while blocks remain open; emitted CLOSE carries the final Block ID.
 * RESET or STOP_SENDING of a live reliable block fails the connection. */
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
