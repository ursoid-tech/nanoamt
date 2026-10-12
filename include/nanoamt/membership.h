#ifndef NANOAMT_MEMBERSHIP_H
#define NANOAMT_MEMBERSHIP_H

#include "nanoamt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NANOAMT_RELAY_ERROR_MEMORY = -10,
  NANOAMT_RELAY_ERROR_LIMIT = -11,
  NANOAMT_RELAY_ERROR_BUFFER = -12,
  NANOAMT_RELAY_ERROR_CRYPTO = -13,
  NANOAMT_RELAY_ERROR_STALE = -14,
  NANOAMT_RELAY_ERROR_POLICY = -15
};
enum { NANOAMT_MEMBERSHIP_ROUTER = 0, NANOAMT_MEMBERSHIP_ENDPOINT = 1 };

typedef struct nanoamt_memberships nanoamt_memberships;
typedef struct nanoamt_membership_config {
  unsigned max_groups;             /* 0: 64 */
  unsigned max_sources;            /* total source records; 0: 1024 */
  unsigned max_sources_per_group;  /* 0: min(64, max_sources) */
  unsigned max_report_records;     /* 0: 1024 */
  uint32_t membership_interval_ms; /* router GMI; 0: 260000 */
  uint32_t last_member_time_ms;    /* router LMQT; 0: 2000 */
  uint8_t mode;                    /* router timers, or immediate per-connection endpoint state */
} nanoamt_membership_config;

typedef struct nanoamt_membership_filter {
  uint8_t group[16];
  uint8_t ip_version;
  uint8_t exclude; /* accept all sources except the returned list */
  size_t source_count;
} nanoamt_membership_filter;

/* Single-threaded objects. Monotonic nonnegative caller clock, below INT64_MAX.
 * apply validates a complete encapsulated IGMP/MLD report before committing.
 * Malformed reports return IGNORED; resource errors leave the object unchanged.
 * Router mode implements RFC 3376/3810 timers without generating queries,
 * as permitted for AMT. Endpoint mode has no autonomous expiry.
 */
nanoamt_memberships *nanoamt_memberships_new(const nanoamt_membership_config *config, int64_t now_ms);
void nanoamt_memberships_free(nanoamt_memberships *state);
nanoamt_memberships *nanoamt_memberships_clone(const nanoamt_memberships *state);
int nanoamt_memberships_apply(nanoamt_memberships *state, int64_t now_ms, const uint8_t *ip, size_t size,
                              unsigned ip_version);
/* Capacity-constrained admission: a valid report commits a bounded subset,
 * continuing withdrawals even if additions exceed state limits. *limited is
 * set when reception was denied. Structural/report bounds remain hard limits;
 * malformed reports still commit nothing. */
int nanoamt_memberships_apply_limited(nanoamt_memberships *state, int64_t now_ms, const uint8_t *ip, size_t size,
                                      unsigned ip_version, int *limited);
int nanoamt_memberships_tick(nanoamt_memberships *state, int64_t now_ms);
int64_t nanoamt_memberships_next_timeout(const nanoamt_memberships *state);
int nanoamt_memberships_allows(const nanoamt_memberships *state, unsigned ip_version, const uint8_t *group,
                               const uint8_t *source);
size_t nanoamt_memberships_count(const nanoamt_memberships *state);
/* Canonical filter at the last tick/apply time. sources is an array of 16-byte
 * addresses (zero padded for IPv4); required count is returned on BUFFER too.
 * No pointers into the object escape, so callers may retain the snapshot.
 */
int nanoamt_memberships_get(const nanoamt_memberships *state, size_t index, nanoamt_membership_filter *filter,
                            uint8_t (*sources)[16], size_t capacity);
/* Packet-set algebra. Output has endpoint semantics and bounds from a.
 * Both inputs should first be ticked to the same caller-clock instant.
 * On error *output is NULL. An empty intersection is an empty state.
 */
int nanoamt_memberships_union(const nanoamt_memberships *a, const nanoamt_memberships *b, nanoamt_memberships **output);
int nanoamt_memberships_intersection(const nanoamt_memberships *a, const nanoamt_memberships *b,
                                     nanoamt_memberships **output);
int nanoamt_memberships_subset(const nanoamt_memberships *a, const nanoamt_memberships *b);

#ifdef __cplusplus
}
#endif
#endif
