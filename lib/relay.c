#include "nanoamt/relay.h"
#include "internal.h"
#include <limits.h>
#include <stdlib.h>

typedef struct relay_client {
  nanoamt_endpoint peer, local;
  nanoamt_memberships *requested, *authorized;
  uint64_t id;
  int64_t until;
  uint32_t mtu;
  uint8_t ecn[2];
  size_t index_entries;
  int timer_pending;
} relay_client;
typedef struct fanout_entry {
  uint8_t group[16], source[16], version, wildcard;
  uint16_t client;
  uint32_t next;
} fanout_entry;
struct nanoamt_relay {
  nanoamt_relay_config config;
  relay_client *clients;
  nanoamt_relay_stats stats;
  uint8_t secret[32], previous[32], qqic;
  int have_previous, error;
  int64_t now, rotate_at, previous_until;
  uint64_t last_id;
  fanout_entry *index;
  uint32_t *buckets;
  uint8_t (*index_sources)[16];
  size_t index_capacity, bucket_count, source_capacity;
  int index_dirty;
  int64_t membership_at;
};
static int64_t after(int64_t now, uint32_t delay) {
  return now > INT64_MAX - delay ? INT64_MAX : now + delay;
}
static void wipe(void *bytes, size_t size) {
  volatile uint8_t *p = bytes;
  while (size--)
    *p++ = 0;
}
static int endpoint_valid(const nanoamt_endpoint *p) {
  unsigned v = ip_version(p->ip_version);
  return (v == 4 || v == 6) && p->port && address_unicast(p->ip, v);
}
static relay_client *find_client(const nanoamt_relay *r, const nanoamt_endpoint *peer, const nanoamt_endpoint *local) {
  for (size_t i = 0; i < r->config.max_clients; ++i)
    if (r->clients[i].id && endpoint_equal(&r->clients[i].peer, peer) && endpoint_equal(&r->clients[i].local, local))
      return r->clients + i;
  return NULL;
}
static size_t index_size(const nanoamt_memberships *state) {
  size_t count = 0;
  for (size_t i = 0; i < nanoamt_memberships_count(state); ++i) {
    nanoamt_membership_filter f;
    (void)nanoamt_memberships_get(state, i, &f, NULL, 0);
    count += f.exclude ? 1 : f.source_count;
  }
  return count;
}
/* Reserve all allocation before the native transaction; rebuild itself cannot
 * fail due to allocation after the corresponding membership commit. */
static int index_reserve(nanoamt_relay *r, size_t needed) {
  if (needed > r->config.max_fanout_entries)
    return NANOAMT_RELAY_ERROR_LIMIT;
  if (needed <= r->index_capacity)
    return NANOAMT_OK;
  size_t capacity = r->index_capacity ? r->index_capacity : 16;
  while (capacity < needed)
    capacity *= 2;
  if (capacity > r->config.max_fanout_entries)
    capacity = r->config.max_fanout_entries;
  size_t buckets = 32;
  while (buckets < capacity * 2)
    buckets *= 2;
  fanout_entry *index = malloc(capacity * sizeof(*index));
  uint32_t *heads = malloc(buckets * sizeof(*heads));
  if (!index || !heads) {
    free(index);
    free(heads);
    return NANOAMT_RELAY_ERROR_MEMORY;
  }
  free(r->index);
  free(r->buckets);
  r->index = index;
  r->buckets = heads;
  r->index_capacity = capacity;
  r->bucket_count = buckets;
  r->index_dirty = 1;
  return NANOAMT_OK;
}
static void timers(nanoamt_relay *r) {
  r->membership_at = INT64_MAX;
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    const relay_client *c = r->clients + i;
    if (!c->id)
      continue;
    if (c->until < r->membership_at)
      r->membership_at = c->until;
    int64_t at = nanoamt_memberships_next_timeout(c->requested);
    if (at < r->membership_at)
      r->membership_at = at;
  }
}
static void delete_client(nanoamt_relay *r, relay_client *c) {
  nanoamt_memberships_free(c->requested);
  nanoamt_memberships_free(c->authorized);
  r->stats.fanout_entries -= c->index_entries;
  r->index_dirty = 1;
  memset(c, 0, sizeof(*c));
  --r->stats.clients;
}
static unsigned qqic_value(unsigned code) {
  return code < 128 ? code : ((code & 15u) | 16u) << (((code >> 4) & 7u) + 3);
}
static unsigned response_value(unsigned milliseconds) {
  unsigned units = (milliseconds + 99u) / 100u;
  if (units < 128)
    return units * 100;
  unsigned code = 128;
  while (code < 255 && qqic_value(code) < units)
    ++code;
  return qqic_value(code) * 100;
}
nanoamt_relay *nanoamt_relay_new(const nanoamt_relay_config *config, int64_t now) {
  if (!config || !config->random_bytes || !config->response_mac || now < 0 || now == INT64_MAX)
    return NULL;
  nanoamt_relay_config c = *config;
  if (!c.max_clients)
    c.max_clients = 64;
  if (!c.max_fanout_entries)
    c.max_fanout_entries = 65536;
  if (!c.max_clients_per_ip)
    c.max_clients_per_ip = c.max_clients < 16 ? c.max_clients : 16;
  if (!c.query_interval_ms)
    c.query_interval_ms = 125000;
  if (!c.query_response_ms)
    c.query_response_ms = 10000;
  if (!c.robustness)
    c.robustness = 2;
  if (!c.secret_interval_ms)
    c.secret_interval_ms = 7200000;
  if (!c.path_mtu)
    c.path_mtu = 1500;
  if (!c.minimum_path_mtu)
    c.minimum_path_mtu = 576;
  if (c.max_fanout_entries > 1048576 || c.max_clients > 1024 || c.max_clients_per_ip > c.max_clients ||
      c.robustness > 7 || c.query_response_ms < 10000 || c.query_response_ms > 3174400 ||
      c.query_interval_ms > 31744000 || c.query_interval_ms <= c.query_response_ms || c.path_mtu > 65535 ||
      c.minimum_path_mtu < 68 || c.path_mtu < c.minimum_path_mtu || c.path_mtu < 1280 ||
      (!zero(c.advertised4.ip, 4) && !address_unicast(c.advertised4.ip, 4)) ||
      (!zero(c.advertised6.ip, 16) && !address_unicast(c.advertised6.ip, 6)) ||
      (!zero(c.query_source4, 4) && !address_unicast(c.query_source4, 4)) ||
      (!zero(c.query_source6, 16) && !address_unicast(c.query_source6, 6)))
    return NULL;
  unsigned qqic = 1, seconds = (c.query_interval_ms + 999u) / 1000u;
  while (qqic < 255 && qqic_value(qqic) < seconds)
    ++qqic;
  c.query_interval_ms = qqic_value(qqic) * 1000;
  c.query_response_ms = response_value(c.query_response_ms);
  if (c.query_response_ms >= c.query_interval_ms)
    return NULL;
  c.memberships.mode = NANOAMT_MEMBERSHIP_ROUTER;
  c.memberships.membership_interval_ms = c.robustness * c.query_interval_ms + c.query_response_ms;
  if (!c.memberships.last_member_time_ms)
    c.memberships.last_member_time_ms = c.robustness * 1000;
  if (c.secret_interval_ms < c.memberships.membership_interval_ms)
    return NULL; /* Two key generations must cover all live cookies. */
  c.aggregate.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  if (!c.aggregate.max_groups)
    c.aggregate.max_groups = 1024;
  if (!c.aggregate.max_sources)
    c.aggregate.max_sources = 4096;
  if (!c.aggregate.max_sources_per_group)
    c.aggregate.max_sources_per_group = c.aggregate.max_sources < 1024 ? c.aggregate.max_sources : 1024;
  nanoamt_memberships *probe = nanoamt_memberships_new(&c.memberships, now);
  if (!probe)
    return NULL;
  nanoamt_memberships_free(probe);
  probe = nanoamt_memberships_new(&c.aggregate, now);
  if (!probe)
    return NULL;
  nanoamt_memberships_free(probe);
  nanoamt_relay *r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->config = c;
  r->qqic = (uint8_t)qqic;
  r->now = now;
  r->membership_at = INT64_MAX;
  r->source_capacity = c.memberships.max_sources_per_group;
  if (!r->source_capacity) {
    unsigned sources = c.memberships.max_sources ? c.memberships.max_sources : 1024;
    r->source_capacity = sources < 64 ? sources : 64;
  }
  r->index_sources = malloc(r->source_capacity * sizeof(*r->index_sources));
  r->rotate_at = after(now, c.secret_interval_ms);
  r->clients = calloc(c.max_clients, sizeof(*r->clients));
  if (!r->index_sources || !r->clients || c.random_bytes(c.random_context, r->secret, sizeof(r->secret))) {
    nanoamt_relay_free(r);
    return NULL;
  }
  return r;
}
void nanoamt_relay_free(nanoamt_relay *r) {
  if (r) {
    if (r->clients)
      for (size_t i = 0; i < r->config.max_clients; ++i)
        if (r->clients[i].id)
          delete_client(r, r->clients + i);
    free(r->clients);
    free(r->index_sources);
    free(r->index);
    free(r->buckets);
    /* Do not leave long-lived cookie keys in a reusable heap block. */
    wipe(r->secret, sizeof(r->secret));
    wipe(r->previous, sizeof(r->previous));
    free(r);
  }
}
int nanoamt_relay_tick(nanoamt_relay *r, int64_t now) {
  if (!r || now < r->now || now == INT64_MAX)
    return NANOAMT_ERROR_ARGUMENT;
  r->now = now;
  if (r->error)
    return r->error;
  if (now >= r->rotate_at) {
    uint8_t key[32];
    if (r->config.random_bytes(r->config.random_context, key, sizeof(key))) {
      wipe(key, sizeof(key));
      return r->error = NANOAMT_ERROR_RANDOM;
    }
    memcpy(r->previous, r->secret, sizeof(r->secret));
    memcpy(r->secret, key, sizeof(key));
    wipe(key, sizeof(key));
    r->have_previous = 1;
    r->previous_until = after(now, r->config.memberships.membership_interval_ms);
    r->rotate_at = after(now, r->config.secret_interval_ms);
  }
  if (r->have_previous && now >= r->previous_until) {
    r->have_previous = 0;
    wipe(r->previous, sizeof(r->previous));
  }
  if (now < r->membership_at)
    return NANOAMT_OK;
  ++r->stats.timer_scans;
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    relay_client *c = r->clients + i;
    if (!c->id)
      continue;
    if (now >= c->until) {
      delete_client(r, c);
      ++r->stats.expired;
      continue;
    }
    int due = c->timer_pending || now >= nanoamt_memberships_next_timeout(c->requested);
    c->timer_pending = due;
    nanoamt_memberships_tick(c->requested, now);
    nanoamt_memberships_tick(c->authorized, now);
    if (due) {
      nanoamt_memberships *intersection = NULL;
      int rc = nanoamt_memberships_intersection(c->authorized, c->requested, &intersection);
      if (rc == NANOAMT_RELAY_ERROR_LIMIT) {
        nanoamt_membership_config empty = r->config.memberships;
        empty.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
        intersection = nanoamt_memberships_new(&empty, now);
        rc = intersection ? NANOAMT_OK : NANOAMT_RELAY_ERROR_MEMORY;
      }
      if (rc)
        return rc;
      size_t count = index_size(intersection), others = r->stats.fanout_entries - c->index_entries;
      if (count > r->config.max_fanout_entries - others) {
        nanoamt_memberships_free(intersection);
        nanoamt_membership_config empty = r->config.memberships;
        empty.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
        intersection = nanoamt_memberships_new(&empty, now);
        if (!intersection)
          return NANOAMT_RELAY_ERROR_MEMORY;
        count = 0;
        ++r->stats.limited;
      }
      rc = index_reserve(r, others + count);
      if (rc) {
        nanoamt_memberships_free(intersection);
        return rc;
      }
      nanoamt_memberships_free(c->authorized);
      c->authorized = intersection;
      r->stats.fanout_entries = others + count;
      c->index_entries = count;
      c->timer_pending = 0;
      r->index_dirty = 1;
    }
  }
  timers(r);
  return NANOAMT_OK;
}
int64_t nanoamt_relay_next_timeout(const nanoamt_relay *r) {
  if (!r || r->error)
    return INT64_MAX;
  int64_t next = r->rotate_at;
  if (r->have_previous && r->previous_until < next)
    next = r->previous_until;
  if (r->membership_at < next)
    next = r->membership_at;
  return next;
}
static int mac(nanoamt_relay *r, const uint8_t key[32], const nanoamt_endpoint *peer, const uint8_t nonce[4],
               unsigned inner, unsigned ecn, uint8_t output[6]) {
  uint8_t input[26] = {0};
  unsigned outer = ip_version(peer->ip_version);
  input[0] = (uint8_t)outer;
  memcpy(input + 1, peer->ip, ip_address_size(outer));
  write16(input + 17, peer->port);
  memcpy(input + 19, nonce, 4);
  input[23] = (uint8_t)inner;
  input[24] = (uint8_t)ecn;
  if (r->config.response_mac(r->config.mac_context, key, input, 25, output))
    return r->error = NANOAMT_RELAY_ERROR_CRYPTO;
  return NANOAMT_OK;
}
static int verify(nanoamt_relay *r, const nanoamt_endpoint *peer, const uint8_t *nonce, const uint8_t *cookie,
                  unsigned inner, unsigned *ecn) {
  unsigned matched = 0, capability = 0;
  for (unsigned v = inner ? inner : 4; v <= (inner ? inner : 6); v += 2)
    for (unsigned old = 0; old < (r->have_previous ? 2u : 1u); ++old)
      for (unsigned e = 0; e < 2; ++e) {
        uint8_t calculated[6];
        int rc = mac(r, old ? r->previous : r->secret, peer, nonce, v, e, calculated);
        if (rc)
          return rc;
        unsigned difference = 0;
        for (size_t i = 0; i < 6; ++i)
          difference |= calculated[i] ^ cookie[i];
        unsigned equal = difference == 0;
        matched |= equal;
        if (equal)
          capability = e;
      }
  if (!matched) {
    ++r->stats.bad_mac;
    return NANOAMT_IGNORED;
  }
  *ecn = capability;
  return NANOAMT_OK;
}
static int aggregate(nanoamt_relay *r, const relay_client *replace, const nanoamt_memberships *candidate,
                     nanoamt_memberships **output) {
  *output = nanoamt_memberships_new(&r->config.aggregate, r->now);
  if (!*output)
    return NANOAMT_RELAY_ERROR_MEMORY;
  for (size_t i = 0; i <= r->config.max_clients; ++i) {
    const relay_client *c = i < r->config.max_clients ? r->clients + i : NULL;
    const nanoamt_memberships *state = c == replace ? candidate : c && c->id ? c->authorized : NULL;
    if (!c && !replace)
      state = candidate;
    if (!state)
      continue;
    /* Data-path ticks skip non-due clients; algebra needs matching clocks. */
    if (c && c != replace && c->id)
      nanoamt_memberships_tick(c->authorized, r->now);
    nanoamt_memberships *merged = NULL;
    int rc = nanoamt_memberships_union(*output, state, &merged);
    if (rc) {
      nanoamt_memberships_free(*output);
      *output = NULL;
      return rc;
    }
    nanoamt_memberships_free(*output);
    *output = merged;
  }
  return NANOAMT_OK;
}
int nanoamt_relay_snapshot(nanoamt_relay *r, int64_t now, nanoamt_memberships **output) {
  if (!output)
    return NANOAMT_ERROR_ARGUMENT;
  *output = NULL;
  int rc = nanoamt_relay_tick(r, now);
  return rc ? rc : aggregate(r, NULL, NULL, output);
}
static int update(nanoamt_relay *r, const nanoamt_endpoint *peer, const nanoamt_endpoint *local, const uint8_t *p,
                  size_t n) {
  if (n < 13)
    return NANOAMT_IGNORED;
  unsigned version = p[12] >> 4, ecn = 0;
  if (version != 4 && version != 6)
    return NANOAMT_IGNORED;
  int rc = verify(r, peer, p + 8, p + 2, version, &ecn);
  if (rc)
    return rc;
  relay_client *c = find_client(r, peer, local);
  if (c) {
    nanoamt_memberships_tick(c->requested, r->now);
    nanoamt_memberships_tick(c->authorized, r->now);
  }
  nanoamt_memberships *candidate =
      c ? nanoamt_memberships_clone(c->requested) : nanoamt_memberships_new(&r->config.memberships, r->now);
  if (!candidate)
    return NANOAMT_RELAY_ERROR_MEMORY;
  int limited = 0;
  rc = nanoamt_memberships_apply_limited(candidate, r->now, p + 12, n - 12, version, &limited);
  if (limited)
    ++r->stats.limited;
  if (rc) {
    nanoamt_memberships_free(candidate);
    if (rc == NANOAMT_IGNORED)
      ++r->stats.malformed;
    else if (rc == NANOAMT_RELAY_ERROR_LIMIT)
      ++r->stats.limited;
    return rc == NANOAMT_RELAY_ERROR_LIMIT ? NANOAMT_IGNORED : rc;
  }
  if (!c) {
    unsigned per_ip = 0;
    relay_client *slot = NULL;
    for (size_t i = 0; i < r->config.max_clients; ++i) {
      relay_client *other = r->clients + i;
      if (!other->id)
        slot = other;
      else if (ip_version(other->peer.ip_version) == ip_version(peer->ip_version) &&
               !memcmp(other->peer.ip, peer->ip, ip_address_size(peer->ip_version)))
        ++per_ip;
    }
    if (!slot || per_ip >= r->config.max_clients_per_ip || r->last_id == UINT64_MAX) {
      nanoamt_memberships_free(candidate);
      ++r->stats.limited;
      return NANOAMT_IGNORED;
    }
    if (!nanoamt_memberships_count(candidate)) {
      nanoamt_memberships_free(candidate);
      return NANOAMT_OK;
    }
    c = slot;
  }
  nanoamt_memberships *merged = NULL, *authorized = NULL, *retained = NULL;
  rc = aggregate(r, c->id ? c : NULL, candidate, &merged);
  int aggregate_limit = rc == NANOAMT_RELAY_ERROR_LIMIT;
  int denied = aggregate_limit || limited;
  if (rc && !aggregate_limit) {
    nanoamt_memberships_free(candidate);
    return rc;
  }
  /* Allocate both outcomes BEFORE the native authorization transaction. Once
   * native joins succeed, the protocol commit must not require an allocation. */
  nanoamt_membership_config empty_config = r->config.memberships;
  empty_config.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  nanoamt_memberships *empty = nanoamt_memberships_new(&empty_config, r->now);
  rc = empty ? nanoamt_memberships_union(empty, candidate, &authorized) : NANOAMT_RELAY_ERROR_MEMORY;
  if (!rc && c->id)
    rc = nanoamt_memberships_intersection(c->authorized, candidate, &retained);
  if (rc == NANOAMT_RELAY_ERROR_LIMIT) {
    /* A bounded representation may not fit the union of EXCLUDE lists.
     * Deny that reception entirely rather than accidentally grant traffic. */
    rc = NANOAMT_OK;
    denied = 1;
  }
  if (!retained) {
    retained = empty;
    empty = NULL;
  }
  nanoamt_memberships_free(empty);
  if (rc) {
    nanoamt_memberships_free(merged);
    nanoamt_memberships_free(authorized);
    nanoamt_memberships_free(retained);
    nanoamt_memberships_free(candidate);
    return rc;
  }
  size_t others = r->stats.fanout_entries - c->index_entries;
  size_t admitted = authorized ? index_size(authorized) : 0, keeping = index_size(retained);
  if (admitted > r->config.max_fanout_entries - others) {
    denied = 1;
    ++r->stats.limited;
  }
  if (keeping > r->config.max_fanout_entries - others) {
    nanoamt_memberships_free(retained);
    retained = nanoamt_memberships_new(&empty_config, r->now);
    if (!retained)
      rc = NANOAMT_RELAY_ERROR_MEMORY;
    keeping = 0;
    ++r->stats.limited;
  }
  if (!rc)
    rc = index_reserve(r, others + (denied ? keeping : admitted > keeping ? admitted : keeping));
  if (rc) {
    nanoamt_memberships_free(merged);
    nanoamt_memberships_free(authorized);
    nanoamt_memberships_free(retained);
    nanoamt_memberships_free(candidate);
    return rc;
  }
  if (!denied && r->config.authorize)
    denied = r->config.authorize(r->config.authorize_context, peer, candidate, merged) != 0;
  nanoamt_memberships_free(merged);
  if (denied) {
    ++r->stats.denied;
    nanoamt_memberships_free(authorized);
    authorized = retained;
  } else
    nanoamt_memberships_free(retained);
  if (!c->id) {
    c->id = ++r->last_id;
    c->mtu = r->config.path_mtu;
    ++r->stats.clients;
  }
  c->peer = *peer;
  c->local = *local;
  nanoamt_memberships_free(c->requested);
  nanoamt_memberships_free(c->authorized);
  c->requested = candidate;
  c->authorized = authorized;
  c->index_entries = denied ? keeping : admitted;
  r->stats.fanout_entries = others + c->index_entries;
  r->index_dirty = 1;
  c->until = after(r->now, r->config.memberships.membership_interval_ms);
  c->ecn[version == 6] = (uint8_t)ecn;
  ++r->stats.updates;
  timers(r);
  return NANOAMT_OK;
}
int nanoamt_relay_receive(nanoamt_relay *r, int64_t now, const nanoamt_endpoint *peer, const nanoamt_endpoint *local,
                          const uint8_t *p, size_t n, nanoamt_relay_control *out) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!peer || !local || (!p && n) || !out || !endpoint_valid(peer) || !endpoint_valid(local) ||
      ip_version(peer->ip_version) != ip_version(local->ip_version))
    return NANOAMT_ERROR_ARGUMENT;
  int rc = nanoamt_relay_tick(r, now);
  if (rc)
    return rc;
  if (n < 2 || p[0] >> 4)
    return NANOAMT_IGNORED;
  if (p[0] == MEMBERSHIP_UPDATE)
    return update(r, peer, local, p, n);
  if (p[0] == TEARDOWN) {
    if (n != 30)
      return NANOAMT_IGNORED;
    nanoamt_endpoint old = {0};
    old.port = read16(p + 12);
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    old.ip_version = (uint8_t)(!memcmp(p + 14, mapped, 12) ? 4 : 6);
    memcpy(old.ip, p + (old.ip_version == 4 ? 26 : 14), ip_address_size(old.ip_version));
    if (!endpoint_valid(&old))
      return NANOAMT_IGNORED;
    unsigned ecn;
    rc = verify(r, &old, p + 8, p + 2, 0, &ecn);
    if (rc)
      return rc;
    for (size_t i = 0; i < r->config.max_clients; ++i)
      if (r->clients[i].id && endpoint_equal(&r->clients[i].peer, &old))
        delete_client(r, r->clients + i);
    timers(r);
    ++r->stats.teardowns;
    return NANOAMT_OK;
  }
  if (p[0] != RELAY_DISCOVERY && p[0] != RELAY_REQUEST)
    return NANOAMT_IGNORED;
  if (n != 8 || (p[0] == RELAY_DISCOVERY && zero(p + 4, 4)))
    return NANOAMT_IGNORED;
  out->source = *local;
  out->destination = *peer;
  memcpy(out->bytes + (p[0] == RELAY_DISCOVERY ? 4 : 8), p + 4, 4);
  if (p[0] == RELAY_DISCOVERY) {
    unsigned version = ip_version(local->ip_version);
    const nanoamt_endpoint *advertised = version == 4 ? &r->config.advertised4 : &r->config.advertised6;
    out->bytes[0] = RELAY_ADVERTISEMENT;
    out->size = 8 + ip_address_size(version);
    memcpy(out->bytes + 8, zero(advertised->ip, ip_address_size(version)) ? local->ip : advertised->ip,
           ip_address_size(version));
    ++r->stats.discoveries;
  } else {
    unsigned version = (p[1] & 1u) ? 6 : 4, ecn = (p[1] >> 1) & 1u;
    out->bytes[0] = MEMBERSHIP_QUERY;
    out->bytes[1] = (uint8_t)(1u | (r->stats.clients == r->config.max_clients ? 2u : 0u));
    rc = mac(r, r->secret, peer, p + 4, version, ecn, out->bytes + 2);
    if (rc) {
      memset(out, 0, sizeof(*out));
      return rc;
    }
    size_t length = nanoamt_general_query(out->bytes + 12, version,
                                          version == 4 ? r->config.query_source4 : r->config.query_source6, r->qqic,
                                          r->config.robustness, r->config.query_response_ms);
    uint8_t *address = out->bytes + 12 + length;
    write16(address, peer->port);
    if (ip_version(peer->ip_version) == 4) {
      address[12] = address[13] = 255;
      memcpy(address + 14, peer->ip, 4);
    } else
      memcpy(address + 2, peer->ip, 16);
    out->size = 12 + length + 18;
    ++r->stats.requests;
  }
  return NANOAMT_PACKET;
}
int nanoamt_relay_set_path_mtu(nanoamt_relay *r, int64_t now, const nanoamt_endpoint *peer,
                               const nanoamt_endpoint *local, uint32_t mtu) {
  if (!r || !peer || !local || mtu < r->config.minimum_path_mtu || mtu > 65535 ||
      (ip_version(local->ip_version) == 6 && mtu < 1280))
    return NANOAMT_ERROR_ARGUMENT;
  int rc = nanoamt_relay_tick(r, now);
  if (rc)
    return rc;
  relay_client *c = find_client(r, peer, local);
  if (!c)
    return NANOAMT_IGNORED;
  c->mtu = mtu;
  return NANOAMT_OK;
}
static uint32_t tunnel_mtu(const relay_client *c) {
  return c->mtu - (ip_version(c->local.ip_version) == 6 ? 50u : 30u);
}
static int allowed(const relay_client *c, const ip_packet *ip) {
  return c->id && nanoamt_memberships_allows(c->requested, ip->version, ip->destination, ip->source) &&
         nanoamt_memberships_allows(c->authorized, ip->version, ip->destination, ip->source);
}
static int ssm(const ip_packet *ip) {
  return ip->version == 4 ? ip->destination[0] == 232
                          : (ip->destination[1] & 0xf0u) == 0x30u && zero(ip->destination + 2, 2);
}
static int forwardable(const ip_packet *ip) {
  return address_unicast(ip->source, ip->version) && multicast(ip->destination, ip->version) && ip->ttl &&
         (ip->version == 4 ? !(ip->destination[0] == 224 && !ip->destination[1] && !ip->destination[2])
                           : (ip->destination[1] & 15u) > 2);
}
static int mtu_blocked(const uint8_t *bytes, const ip_packet *ip, uint32_t mtu) {
  return ip->size > mtu && (ip->version == 6 || (read16(bytes + 6) & 0x4000u) || mtu < (bytes[0] & 15u) * 4u + 8u);
}
static size_t index_hash(unsigned version, const uint8_t *group, const uint8_t *source, size_t mask) {
  uint64_t h = UINT64_C(14695981039346656037) ^ version;
  size_t n = ip_address_size(version);
  for (size_t i = 0; i < n; ++i)
    h = (h ^ group[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < n; ++i)
    h = (h ^ (source ? source[i] : 0)) * UINT64_C(1099511628211);
  return (size_t)(h ^ (h >> 32)) & mask;
}
static int index_rebuild(nanoamt_relay *r) {
  if (!r->index_dirty)
    return NANOAMT_OK;
  if (r->bucket_count)
    memset(r->buckets, 0, r->bucket_count * sizeof(*r->buckets));
  size_t at = 0;
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    relay_client *c = r->clients + i;
    if (!c->id)
      continue;
    for (size_t j = 0; j < nanoamt_memberships_count(c->authorized); ++j) {
      nanoamt_membership_filter filter;
      int rc = nanoamt_memberships_get(c->authorized, j, &filter, r->index_sources, r->source_capacity);
      if (rc)
        return rc;
      size_t count = filter.exclude ? 1 : filter.source_count;
      for (size_t k = 0; k < count; ++k) {
        if (at == r->index_capacity)
          return NANOAMT_RELAY_ERROR_LIMIT;
        fanout_entry *entry = r->index + at;
        memset(entry, 0, sizeof(*entry));
        entry->client = (uint16_t)i;
        entry->version = filter.ip_version;
        entry->wildcard = filter.exclude;
        memcpy(entry->group, filter.group, 16);
        if (!filter.exclude)
          memcpy(entry->source, r->index_sources[k], 16);
        size_t hash =
            index_hash(entry->version, entry->group, entry->wildcard ? NULL : entry->source, r->bucket_count - 1);
        entry->next = r->buckets[hash];
        r->buckets[hash] = (uint32_t)++at;
      }
    }
  }
  r->index_dirty = 0;
  ++r->stats.fanout_rebuilds;
  return NANOAMT_OK;
}
static void index_candidates(nanoamt_relay *r, const ip_packet *ip, uint8_t *eligible, int wildcard) {
  if (!r->bucket_count)
    return;
  size_t hash = index_hash(ip->version, ip->destination, wildcard ? NULL : ip->source, r->bucket_count - 1);
  for (uint32_t at = r->buckets[hash]; at; at = r->index[at - 1].next) {
    const fanout_entry *entry = r->index + at - 1;
    ++r->stats.fanout_candidates;
    if (entry->version != ip->version || entry->wildcard != wildcard ||
        memcmp(entry->group, ip->destination, ip_address_size(ip->version)) ||
        (!wildcard && memcmp(entry->source, ip->source, ip_address_size(ip->version))))
      continue;
    size_t i = entry->client;
    if (allowed(r->clients + i, ip))
      eligible[i / 8] |= (uint8_t)(1u << (i % 8));
  }
}
static size_t eligible_next(const nanoamt_relay_forward *f, size_t start, size_t limit) {
  while (start < limit) {
    uint8_t bits = (uint8_t)(f->eligible[start / 8] & (uint8_t)(255u << (start % 8)));
    if (!bits) {
      start = (start / 8 + 1) * 8;
      continue;
    }
    while (!(bits & (1u << (start % 8))))
      ++start;
    return start < limit ? start : limit;
  }
  return limit;
}
int nanoamt_relay_forward_begin(nanoamt_relay *r, int64_t now, const uint8_t *bytes, size_t size,
                                nanoamt_relay_forward *f) {
  if (!f || (!bytes && size))
    return NANOAMT_ERROR_ARGUMENT;
  memset(f, 0, sizeof(*f));
  int rc = nanoamt_relay_tick(r, now);
  if (rc)
    return rc;
  ip_packet ip;
  if (!nanoamt_ip_forward_decode(bytes, size, &ip) || ip.size != size || !forwardable(&ip))
    return NANOAMT_IGNORED;
  f->owner = r;
  f->ip = bytes;
  f->size = size;
  f->max_tunnel_id = r->last_id;
  rc = index_rebuild(r);
  if (rc)
    return rc;
  index_candidates(r, &ip, f->eligible, 0);
  index_candidates(r, &ip, f->eligible, 1);
  for (size_t i = eligible_next(f, 0, r->config.max_clients); i < r->config.max_clients;
       i = eligible_next(f, i + 1, r->config.max_clients)) {
    relay_client *c = r->clients + i;
    uint32_t mtu = tunnel_mtu(c);
    if (mtu_blocked(bytes, &ip, mtu)) {
      ++r->stats.mtu_drops;
      if (ssm(&ip) && (!f->feedback_mtu || mtu < f->feedback_mtu))
        f->feedback_mtu = mtu;
    }
  }
  return NANOAMT_OK;
}
static size_t copied_header(const uint8_t *ip, uint8_t *out) {
  size_t old = (ip[0] & 15u) * 4u, at = 20;
  memcpy(out, ip, 20);
  for (size_t i = 20; i < old;) {
    unsigned type = ip[i];
    if (!type)
      break;
    if (type == 1) {
      ++i;
      continue;
    }
    size_t length = ip[i + 1];
    if (type & 0x80u) {
      memcpy(out + at, ip + i, length);
      at += length;
    }
    i += length;
  }
  while (at % 4)
    out[at++] = 0;
  out[0] = (uint8_t)(0x40u | (at / 4));
  return at;
}
int nanoamt_relay_forward_next(nanoamt_relay *r, int64_t now, nanoamt_relay_forward *f, uint8_t *bytes, size_t capacity,
                               nanoamt_relay_output *out) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!r || !f || f->owner != r || !out || (!bytes && capacity))
    return NANOAMT_ERROR_ARGUMENT;
  int rc = nanoamt_relay_tick(r, now);
  if (rc)
    return rc;
  ip_packet ip;
  if (!nanoamt_ip_forward_decode(f->ip, f->size, &ip))
    return NANOAMT_ERROR_ARGUMENT;
  if (!f->feedback_done) {
    /* Recompute at emission: a leave or PMTU change can occur while the
     * caller retains a cursor or a previous output under backpressure. */
    f->feedback_mtu = 0;
    for (size_t i = eligible_next(f, f->client, r->config.max_clients); i < r->config.max_clients;
         i = eligible_next(f, i + 1, r->config.max_clients)) {
      relay_client *c = r->clients + i;
      if (!(f->eligible[i / 8] & (1u << (i % 8))) || c->id > f->max_tunnel_id || !allowed(c, &ip))
        continue;
      uint32_t mtu = tunnel_mtu(c);
      if (ssm(&ip) && mtu_blocked(f->ip, &ip, mtu) && (!f->feedback_mtu || mtu < f->feedback_mtu))
        f->feedback_mtu = mtu;
    }
  }
  if (f->feedback_mtu) {
    out->size = f->size;
    if (capacity < f->size)
      return NANOAMT_RELAY_ERROR_BUFFER;
    memcpy(bytes, f->ip, f->size);
    out->kind = NANOAMT_RELAY_MTU_FEEDBACK;
    out->mtu = f->feedback_mtu;
    out->destination.ip_version = ip.version;
    memcpy(out->destination.ip, ip.source, ip_address_size(ip.version));
    f->feedback_mtu = 0;
    f->feedback_done = 1;
    return NANOAMT_PACKET;
  }
  while ((f->client = eligible_next(f, f->client, r->config.max_clients)) < r->config.max_clients) {
    relay_client *c = r->clients + f->client;
    uint32_t mtu = tunnel_mtu(c);
    if (!(f->eligible[f->client / 8] & (1u << (f->client % 8))) || c->id > f->max_tunnel_id || !allowed(c, &ip) ||
        mtu_blocked(f->ip, &ip, mtu)) {
      ++f->client;
      f->offset = 0;
      continue;
    }
    size_t produced, take = 0;
    uint8_t header[60];
    if (f->size <= mtu && !f->offset) {
      produced = f->size;
      if (capacity < produced + 2) {
        out->size = produced + 2;
        return NANOAMT_RELAY_ERROR_BUFFER;
      }
      memcpy(bytes + 2, f->ip, produced);
    } else {
      size_t original_header = (f->ip[0] & 15u) * 4u;
      unsigned original_flags = read16(f->ip + 6);
      size_t length;
      if (!f->offset && !(original_flags & 0x1fffu)) {
        length = original_header;
        memcpy(header, f->ip, length);
      } else
        length = copied_header(f->ip, header);
      size_t remaining = f->size - original_header - f->offset;
      take = remaining < mtu - length ? remaining : (mtu - length) & ~(size_t)7;
      if (!take)
        return NANOAMT_ERROR_ARGUMENT;
      produced = length + take;
      if (capacity < produced + 2) {
        out->size = produced + 2;
        return NANOAMT_RELAY_ERROR_BUFFER;
      }
      unsigned flags = (original_flags & 0x1fffu) + (unsigned)(f->offset / 8);
      if (take < remaining || (original_flags & 0x2000u))
        flags |= 0x2000u;
      write16(header + 6, (uint16_t)flags);
      write16(header + 2, (uint16_t)produced);
      write16(header + 10, 0);
      write16(header + 10, nanoamt_checksum(header, length, 0));
      memcpy(bytes + 2, header, length);
      memcpy(bytes + 2 + length, f->ip + original_header + f->offset, take);
    }
    bytes[0] = MULTICAST_DATA;
    bytes[1] = 0;
    out->source = c->local;
    out->destination = c->peer;
    out->tunnel_id = c->id;
    out->client_slot = (uint16_t)f->client;
    out->size = produced + 2;
    out->tos = c->ecn[ip.version == 6] ? ip.tos & 3u : 0;
    out->dont_fragment = 1;
    ++r->stats.data_packets;
    r->stats.data_bytes += out->size;
    if (take)
      f->offset += take;
    if (!take || f->offset == f->size - (f->ip[0] & 15u) * 4u) {
      ++f->client;
      f->offset = 0;
    }
    return NANOAMT_PACKET;
  }
  return NANOAMT_OK;
}
int nanoamt_relay_output_valid(nanoamt_relay *r, int64_t now, const nanoamt_relay_output *out, const uint8_t *bytes,
                               size_t size) {
  if (!out || !bytes || size != out->size || out->kind != NANOAMT_RELAY_DATA || size < 3 ||
      bytes[0] != MULTICAST_DATA || bytes[1])
    return 0;
  if (nanoamt_relay_tick(r, now))
    return 0;
  relay_client *c = out->client_slot < r->config.max_clients ? r->clients + out->client_slot : NULL;
  ip_packet ip;
  return c && c->id && c->id == out->tunnel_id && endpoint_equal(&c->peer, &out->destination) &&
         endpoint_equal(&c->local, &out->source) && c->local.scope_id == out->source.scope_id &&
         size - 2 <= tunnel_mtu(c) && nanoamt_ip_forward_decode(bytes + 2, size - 2, &ip) && ip.size == size - 2 &&
         allowed(c, &ip) && out->tos == (c->ecn[ip.version == 6] ? ip.tos & 3u : 0);
}
void nanoamt_relay_get_stats(const nanoamt_relay *r, nanoamt_relay_stats *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
    if (r)
      *out = r->stats;
  }
}
