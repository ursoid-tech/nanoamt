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
} relay_client;
struct nanoamt_relay {
  nanoamt_relay_config config;
  relay_client *clients;
  nanoamt_relay_stats stats;
  uint8_t secret[32], previous[32], qqic;
  int have_previous, error;
  int64_t now, rotate_at, previous_until;
  uint64_t last_id;
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
static void delete_client(nanoamt_relay *r, relay_client *c) {
  nanoamt_memberships_free(c->requested);
  nanoamt_memberships_free(c->authorized);
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
  if (c.max_clients > 1024 || c.max_clients_per_ip > c.max_clients || c.robustness > 7 || c.query_response_ms < 10000 ||
      c.query_response_ms > 3174400 || c.query_interval_ms > 31744000 || c.query_interval_ms <= c.query_response_ms ||
      c.path_mtu > 65535 || c.minimum_path_mtu < 68 || c.path_mtu < c.minimum_path_mtu || c.path_mtu < 1280 ||
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
  r->rotate_at = after(now, c.secret_interval_ms);
  r->clients = calloc(c.max_clients, sizeof(*r->clients));
  if (!r->clients || c.random_bytes(c.random_context, r->secret, sizeof(r->secret))) {
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
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    relay_client *c = r->clients + i;
    if (!c->id)
      continue;
    if (now >= c->until) {
      delete_client(r, c);
      ++r->stats.expired;
      continue;
    }
    int due = now >= nanoamt_memberships_next_timeout(c->requested);
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
      nanoamt_memberships_free(c->authorized);
      c->authorized = intersection;
    }
  }
  return NANOAMT_OK;
}
int64_t nanoamt_relay_next_timeout(const nanoamt_relay *r) {
  if (!r || r->error)
    return INT64_MAX;
  int64_t next = r->rotate_at;
  if (r->have_previous && r->previous_until < next)
    next = r->previous_until;
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    const relay_client *c = r->clients + i;
    if (!c->id)
      continue;
    if (c->until < next)
      next = c->until;
    int64_t timeout = nanoamt_memberships_next_timeout(c->requested);
    if (timeout < next)
      next = timeout;
  }
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
  c->until = after(r->now, r->config.memberships.membership_interval_ms);
  c->ecn[version == 6] = (uint8_t)ecn;
  ++r->stats.updates;
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
  for (size_t i = 0; i < r->config.max_clients; ++i) {
    relay_client *c = r->clients + i;
    if (!allowed(c, &ip))
      continue;
    f->eligible[i / 8] |= (uint8_t)(1u << (i % 8));
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
    for (size_t i = f->client; i < r->config.max_clients; ++i) {
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
  while (f->client < r->config.max_clients) {
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
  relay_client *c = find_client(r, &out->destination, &out->source);
  ip_packet ip;
  return c && c->id == out->tunnel_id && c->local.scope_id == out->source.scope_id && size - 2 <= tunnel_mtu(c) &&
         nanoamt_ip_forward_decode(bytes + 2, size - 2, &ip) && ip.size == size - 2 && allowed(c, &ip) &&
         out->tos == (c->ecn[ip.version == 6] ? ip.tos & 3u : 0);
}
void nanoamt_relay_get_stats(const nanoamt_relay *r, nanoamt_relay_stats *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
    if (r)
      *out = r->stats;
  }
}
