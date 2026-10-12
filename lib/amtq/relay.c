#include "nanoamt/amtq_relay.h"
#include "internal.h"

enum { CONTEXT_FREE, CONTEXT_OPENING, CONTEXT_PENDING, CONTEXT_ACTIVE, CONTEXT_CLOSING };
typedef struct relay_context {
  uint64_t id, next_packet_id;
  int64_t deadline;
  unsigned state;
} relay_context;
struct nanoamtq_relay {
  nanoamtq_relay_config config;
  nanoamt_memberships *requested, *authorized, *pending;
  uint64_t generation, revision, last_context, close_error;
  int error, local_settings, peer_settings, query_pending, awaiting_update, have_nonce, have_context;
  uint8_t ip_version, qqic, request_nonce[4], query_nonce[4];
  int64_t now, deadline, partial_deadline;
  relay_context contexts[NANOAMTQ_MAX_CONTEXTS];
  amtq_control_reader control;
};
struct nanoamtq_authorization {
  const nanoamtq_relay *owner;
  uint64_t connection_id, generation, revision;
  nanoamt_memberships *authorized;
};
static int fail(nanoamtq_relay *r, int error, uint64_t code) {
  r->error = error;
  r->close_error = code;
  return error;
}
static int protocol(nanoamtq_relay *r, uint64_t code) {
  return fail(r, NANOAMTQ_ERROR_PROTOCOL, code);
}
static int local_result(int rc) {
  if (rc == NANOAMT_RELAY_ERROR_MEMORY)
    return NANOAMTQ_ERROR_MEMORY;
  if (rc == NANOAMT_RELAY_ERROR_LIMIT)
    return NANOAMTQ_ERROR_LIMIT;
  return rc ? NANOAMTQ_ERROR_ARGUMENT : NANOAMTQ_OK;
}
static unsigned qqic_value(unsigned code) {
  return code < 128 ? code : ((code & 15u) | 16u) << (((code >> 4) & 7u) + 3);
}
static relay_context *find_context(const nanoamtq_relay *r, uint64_t id) {
  for (unsigned i = 0; i < r->config.max_contexts; ++i)
    if (r->contexts[i].state && r->contexts[i].id == id)
      return (relay_context *)r->contexts + i;
  return NULL;
}
nanoamtq_relay *nanoamtq_relay_new(const nanoamtq_relay_config *config, int64_t now) {
  if (!config || !config->connection_id || now < 0 || now == INT64_MAX ||
      config->peer_max_uni_streams > AMTQ_VARINT_MAX)
    return NULL;
  nanoamtq_relay_config c = *config;
  if (!c.max_contexts)
    c.max_contexts = NANOAMTQ_MAX_CONTEXTS;
  if (!c.control_timeout_ms)
    c.control_timeout_ms = 10000;
  if (!c.query_interval_ms)
    c.query_interval_ms = 125000;
  if (!c.query_response_ms)
    c.query_response_ms = 10000;
  if (!c.robustness)
    c.robustness = 2;
  if (c.max_contexts > NANOAMTQ_MAX_CONTEXTS || c.robustness > 7 || c.query_interval_ms > 31744000 ||
      c.query_response_ms < 10000 || c.query_response_ms > 3174400 || c.query_interval_ms <= c.query_response_ms ||
      (!zero(c.query_source4, 4) && !address_unicast(c.query_source4, 4)) ||
      (!zero(c.query_source6, 16) && !address_unicast(c.query_source6, 6)))
    return NULL;
  unsigned code = 1, seconds = (c.query_interval_ms + 999u) / 1000u;
  while (code < 255 && qqic_value(code) < seconds)
    ++code;
  c.query_interval_ms = qqic_value(code) * 1000u;
  c.memberships.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  nanoamtq_relay *r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->config = c;
  r->qqic = (uint8_t)code;
  r->now = now;
  r->deadline = amtq_after(now, c.control_timeout_ms);
  r->partial_deadline = INT64_MAX;
  r->requested = nanoamt_memberships_new(&c.memberships, now);
  r->authorized = nanoamt_memberships_new(&c.memberships, now);
  if (!r->requested || !r->authorized) {
    nanoamtq_relay_free(r);
    return NULL;
  }
  return r;
}
void nanoamtq_relay_free(nanoamtq_relay *r) {
  if (r) {
    nanoamt_memberships_free(r->requested);
    nanoamt_memberships_free(r->authorized);
    nanoamt_memberships_free(r->pending);
    free(r);
  }
}
int nanoamtq_relay_tick(nanoamtq_relay *r, int64_t now) {
  if (!r || now < r->now || now == INT64_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  if (r->error)
    return r->error;
  r->now = now;
  nanoamt_memberships_tick(r->requested, now);
  nanoamt_memberships_tick(r->authorized, now);
  if (r->pending)
    nanoamt_memberships_tick(r->pending, now);
  if (now >= r->deadline || now >= r->partial_deadline)
    return fail(r, NANOAMTQ_ERROR_TIMEOUT, 0);
  for (unsigned i = 0; i < r->config.max_contexts; ++i)
    if (r->contexts[i].state == CONTEXT_PENDING && now >= r->contexts[i].deadline)
      return fail(r, NANOAMTQ_ERROR_TIMEOUT, 0);
  return NANOAMTQ_OK;
}
int64_t nanoamtq_relay_next_timeout(const nanoamtq_relay *r) {
  if (!r || r->error)
    return INT64_MAX;
  if (!r->local_settings || r->query_pending)
    return r->now;
  int64_t next = r->deadline < r->partial_deadline ? r->deadline : r->partial_deadline;
  for (unsigned i = 0; i < r->config.max_contexts; ++i) {
    const relay_context *c = r->contexts + i;
    if (c->state == CONTEXT_OPENING || c->state == CONTEXT_CLOSING)
      return r->now;
    if (c->state == CONTEXT_PENDING && c->deadline < next)
      next = c->deadline;
  }
  return next;
}
int nanoamtq_relay_error(const nanoamtq_relay *r) {
  return r ? r->error : NANOAMTQ_ERROR_ARGUMENT;
}
uint64_t nanoamtq_relay_close_error(const nanoamtq_relay *r) {
  return r ? r->close_error : 0;
}
int nanoamtq_relay_is_ready(const nanoamtq_relay *r) {
  if (!r || r->error || !r->local_settings || !r->peer_settings)
    return 0;
  for (unsigned i = 0; i < r->config.max_contexts; ++i)
    if (r->contexts[i].state == CONTEXT_ACTIVE)
      return 1;
  return 0;
}
const nanoamt_memberships *nanoamtq_relay_requested(const nanoamtq_relay *r) {
  return r ? (r->pending ? r->pending : r->requested) : NULL;
}
const nanoamt_memberships *nanoamtq_relay_authorized(const nanoamtq_relay *r) {
  return r ? r->authorized : NULL;
}
uint64_t nanoamtq_relay_generation(const nanoamtq_relay *r) {
  return r ? r->generation : 0;
}
int nanoamtq_relay_pending(const nanoamtq_relay *r) {
  return r && r->pending && !r->error;
}
static int copy_bounded(nanoamtq_relay *r, const nanoamt_memberships *state, nanoamt_memberships **output) {
  *output = NULL;
  nanoamt_memberships *copy = nanoamt_memberships_clone(state);
  if (!copy)
    return NANOAMTQ_ERROR_MEMORY;
  int rc = nanoamt_memberships_tick(copy, r->now);
  nanoamt_memberships *empty = NULL;
  if (!rc) {
    empty = nanoamt_memberships_new(&r->config.memberships, r->now);
    rc = empty ? nanoamt_memberships_union(empty, copy, output) : NANOAMT_RELAY_ERROR_MEMORY;
  }
  nanoamt_memberships_free(copy);
  nanoamt_memberships_free(empty);
  return local_result(rc);
}
int nanoamtq_relay_prepare_authorization(nanoamtq_relay *r, int64_t now, uint64_t generation,
                                         const nanoamt_memberships *authorized, nanoamtq_authorization **output) {
  if (!output)
    return NANOAMTQ_ERROR_ARGUMENT;
  *output = NULL;
  if (!r || !authorized)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  if (generation != r->generation)
    return NANOAMTQ_ERROR_STALE;
  if (r->revision == UINT64_MAX)
    return NANOAMTQ_ERROR_LIMIT;
  nanoamt_memberships *copy;
  rc = copy_bounded(r, authorized, &copy);
  if (rc)
    return rc;
  if (!nanoamt_memberships_subset(copy, nanoamtq_relay_requested(r))) {
    nanoamt_memberships_free(copy);
    return NANOAMTQ_ERROR_POLICY;
  }
  nanoamtq_authorization *token = calloc(1, sizeof(*token));
  if (!token) {
    nanoamt_memberships_free(copy);
    return NANOAMTQ_ERROR_MEMORY;
  }
  token->owner = r;
  token->connection_id = r->config.connection_id;
  token->generation = generation;
  token->revision = r->revision;
  token->authorized = copy;
  *output = token;
  return NANOAMTQ_OK;
}
int nanoamtq_relay_commit_authorization(nanoamtq_relay *r, int64_t now, nanoamtq_authorization *token) {
  if (!r || !token)
    return NANOAMTQ_ERROR_ARGUMENT;
  if (token->owner != r || token->connection_id != r->config.connection_id || token->generation != r->generation ||
      token->revision != r->revision || !token->authorized)
    return NANOAMTQ_ERROR_STALE;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  /* Only timestamp changes occur here; endpoint states have no timer expiry. */
  nanoamt_memberships_tick(token->authorized, now);
  if (r->pending) {
    nanoamt_memberships_free(r->requested);
    r->requested = r->pending;
    r->pending = NULL;
    r->deadline = INT64_MAX;
  }
  nanoamt_memberships_free(r->authorized);
  r->authorized = token->authorized;
  token->authorized = NULL;
  ++r->revision;
  return NANOAMTQ_OK;
}
void nanoamtq_relay_authorization_free(nanoamtq_authorization *token) {
  if (token) {
    nanoamt_memberships_free(token->authorized);
    free(token);
  }
}
int nanoamtq_relay_authorize_all(nanoamtq_relay *r, int64_t now, uint64_t generation) {
  nanoamtq_authorization *token = NULL;
  int rc = nanoamtq_relay_prepare_authorization(r, now, generation, nanoamtq_relay_requested(r), &token);
  if (!rc)
    rc = nanoamtq_relay_commit_authorization(r, now, token);
  nanoamtq_relay_authorization_free(token);
  return rc;
}
int nanoamtq_relay_deny(nanoamtq_relay *r, int64_t now, uint64_t generation) {
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  if (generation != r->generation)
    return NANOAMTQ_ERROR_STALE;
  nanoamt_memberships *retained = NULL;
  rc = nanoamt_memberships_intersection(r->authorized, nanoamtq_relay_requested(r), &retained);
  if (rc == NANOAMT_RELAY_ERROR_LIMIT) {
    retained = nanoamt_memberships_new(&r->config.memberships, now);
    rc = retained ? NANOAMT_OK : NANOAMT_RELAY_ERROR_MEMORY;
  }
  nanoamtq_authorization *token = NULL;
  if (!rc)
    rc = nanoamtq_relay_prepare_authorization(r, now, generation, retained, &token);
  else
    rc = local_result(rc);
  if (!rc)
    rc = nanoamtq_relay_commit_authorization(r, now, token);
  nanoamt_memberships_free(retained);
  nanoamtq_relay_authorization_free(token);
  return rc;
}

static int valid_record_kinds(const ip_packet *ip) {
  const uint8_t *p = ip->payload;
  size_t n = ip->payload_size, stride = ip_address_size(ip->version);
  if (n < 8)
    return 0;
  if (p[0] != 0x22 && p[0] != 143)
    return 1; /* The shared parser validates legacy message kinds. */
  size_t at = 8;
  for (unsigned i = 0; i < read16(p + 6); ++i) {
    if (n - at < 4 + stride || p[at] < 1 || p[at] > 6)
      return 0;
    size_t length = 4 + stride + (size_t)read16(p + at + 2) * stride + (size_t)p[at + 1] * 4;
    if (length > n - at)
      return 0;
    at += length;
  }
  return at == n;
}
static int receive_record(void *context, uint64_t type, uint8_t *p, size_t n) {
  nanoamtq_relay *r = context;
  if (type == NANOAMTQ_SETTINGS) {
    if (r->peer_settings)
      return protocol(r, NANOAMTQ_CLOSE_SETTINGS);
    uint64_t modes, preferred;
    int rc = amtq_settings_decode(p, n, 0, &modes, &preferred);
    if (rc == NANOAMTQ_ERROR_MEMORY)
      return fail(r, rc, NANOAMTQ_CLOSE_INTERNAL);
    if (rc || ((modes & 2u) && !r->config.peer_max_uni_streams))
      return protocol(r, NANOAMTQ_CLOSE_SETTINGS);
    r->peer_settings = 1;
    if (r->local_settings)
      r->deadline = INT64_MAX;
    return NANOAMTQ_OK;
  }
  if (!r->local_settings || !r->peer_settings)
    return protocol(r, NANOAMTQ_CLOSE_PROTOCOL);
  if (type == NANOAMTQ_CONTEXT || type == NANOAMTQ_CONTEXT_CLOSE)
    return protocol(r, NANOAMTQ_CLOSE_PROTOCOL);
  if (type == NANOAMTQ_CONTEXT_ACK) {
    size_t at = 0;
    uint64_t id;
    if (!amtq_get(p, n, &at, &id) || at != n)
      return protocol(r, NANOAMTQ_CLOSE_PROTOCOL);
    relay_context *c = find_context(r, id);
    if (!c || c->state != CONTEXT_PENDING)
      return protocol(r, NANOAMTQ_CLOSE_CONTEXT);
    c->state = CONTEXT_ACTIVE;
    c->deadline = INT64_MAX;
    return NANOAMTQ_OK;
  }
  if (type != NANOAMTQ_AMT_CONTROL)
    return NANOAMTQ_OK;
  if (n == 8 && p[0] == RELAY_REQUEST) {
    unsigned version = (p[1] & 1u) ? 6 : 4;
    if ((p[1] & ~1u) || p[2] || p[3] || r->query_pending || (r->ip_version && r->ip_version != version))
      return protocol(r, NANOAMTQ_CLOSE_AMT_MESSAGE);
    r->ip_version = (uint8_t)version;
    r->query_pending = 1;
    r->awaiting_update = 0;
    memcpy(r->request_nonce, p + 4, 4);
    r->deadline = amtq_after(r->now, r->config.control_timeout_ms);
    return NANOAMTQ_OK;
  }
  ip_packet ip;
  if (n < 13 || p[0] != MEMBERSHIP_UPDATE || p[1] || !zero(p + 2, 6) || r->query_pending || !r->have_nonce ||
      memcmp(p + 8, r->query_nonce, 4) || !nanoamt_ip_decode(p + 12, n - 12, &ip) || ip.size != n - 12 ||
      ip.version != r->ip_version || !valid_record_kinds(&ip))
    return protocol(r, NANOAMTQ_CLOSE_AMT_MESSAGE);
  if (r->generation == UINT64_MAX)
    return protocol(r, NANOAMTQ_CLOSE_INTERNAL);
  nanoamt_memberships *candidate = nanoamt_memberships_clone(r->requested);
  if (!candidate)
    return fail(r, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
  int rc = nanoamt_memberships_apply(candidate, r->now, p + 12, n - 12, r->ip_version);
  if (rc) {
    nanoamt_memberships_free(candidate);
    if (rc == NANOAMT_RELAY_ERROR_MEMORY)
      return fail(r, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    return protocol(r, rc == NANOAMT_RELAY_ERROR_LIMIT ? NANOAMTQ_CLOSE_EXCESSIVE_LOAD : NANOAMTQ_CLOSE_AMT_MESSAGE);
  }
  r->pending = candidate;
  ++r->generation;
  r->awaiting_update = 0;
  r->deadline = amtq_after(r->now, r->config.control_timeout_ms);
  return NANOAMTQ_MEMBERSHIP;
}
int nanoamtq_relay_receive_control(nanoamtq_relay *r, int64_t now, uint64_t stream, const uint8_t *p, size_t n, int fin,
                                   size_t *consumed) {
  if (!consumed)
    return NANOAMTQ_ERROR_ARGUMENT;
  *consumed = 0;
  if (!p && n)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  if (stream || fin)
    return protocol(r, NANOAMTQ_CLOSE_CONTROL_STREAM);
  if (r->pending)
    return NANOAMTQ_MEMBERSHIP;
  rc = amtq_control_feed(&r->control, p, n, consumed, receive_record, r);
  if (rc < 0 && !r->error)
    return protocol(r, NANOAMTQ_CLOSE_PROTOCOL);
  if (r->control.size && *consumed)
    r->partial_deadline = amtq_after(now, r->config.control_timeout_ms);
  else if (!r->control.size)
    r->partial_deadline = INT64_MAX;
  return rc;
}
int nanoamtq_relay_receive_datagram(nanoamtq_relay *r, int64_t now, const uint8_t *p, size_t n) {
  if (!p && n)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = nanoamtq_relay_tick(r, now);
  return rc ? rc : protocol(r, NANOAMTQ_CLOSE_PROTOCOL);
}
static int emit(nanoamtq_relay *r, nanoamtq_control *out, uint64_t type, const uint8_t *p, size_t n) {
  nanoamtq_record record = {type, p, n};
  if (nanoamtq_record_encode(&record, out->bytes, sizeof(out->bytes), &out->size))
    return protocol(r, NANOAMTQ_CLOSE_INTERNAL);
  return NANOAMTQ_PACKET;
}
int nanoamtq_relay_send(nanoamtq_relay *r, int64_t now, nanoamtq_control *out) {
  if (!out)
    return NANOAMTQ_ERROR_ARGUMENT;
  out->size = 0;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  if (!r->local_settings) {
    const uint8_t settings[] = {0, 1};
    rc = emit(r, out, NANOAMTQ_SETTINGS, settings, sizeof(settings));
    if (rc == NANOAMTQ_PACKET) {
      r->local_settings = 1;
      if (r->peer_settings)
        r->deadline = INT64_MAX;
    }
    return rc;
  }
  if (!r->peer_settings)
    return NANOAMTQ_OK;
  if (r->query_pending) {
    uint8_t query[88] = {4};
    memcpy(query + 8, r->request_nonce, 4);
    size_t n = 12 + nanoamt_general_query(query + 12, r->ip_version,
                                          r->ip_version == 6 ? r->config.query_source6 : r->config.query_source4,
                                          r->qqic, r->config.robustness, r->config.query_response_ms);
    rc = emit(r, out, NANOAMTQ_AMT_CONTROL, query, n);
    if (rc == NANOAMTQ_PACKET) {
      r->query_pending = 0;
      r->awaiting_update = r->have_nonce = 1;
      memcpy(r->query_nonce, r->request_nonce, 4);
      r->deadline = amtq_after(now, r->config.control_timeout_ms);
    }
    return rc;
  }
  relay_context *opening = NULL;
  for (unsigned i = 0; i < r->config.max_contexts; ++i) {
    relay_context *c = r->contexts + i;
    if (c->state == CONTEXT_CLOSING) {
      uint8_t id[8];
      size_t n = amtq_put(id, c->id);
      rc = emit(r, out, NANOAMTQ_CONTEXT_CLOSE, id, n);
      if (rc == NANOAMTQ_PACKET)
        memset(c, 0, sizeof(*c));
      return rc;
    }
    if (c->state == CONTEXT_OPENING && (!opening || c->id < opening->id))
      opening = c;
  }
  if (opening) {
    uint8_t fields[9];
    size_t n = amtq_put(fields, opening->id);
    fields[n++] = 0; /* Datagram Mode. */
    rc = emit(r, out, NANOAMTQ_CONTEXT, fields, n);
    if (rc == NANOAMTQ_PACKET) {
      opening->state = CONTEXT_PENDING;
      opening->deadline = amtq_after(now, r->config.control_timeout_ms);
    }
    return rc;
  }
  return NANOAMTQ_OK;
}
int nanoamtq_relay_open_context(nanoamtq_relay *r, int64_t now, uint64_t id) {
  if (!r || id > AMTQ_VARINT_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  if (!r->local_settings || !r->peer_settings || (!r->have_context && id) || (r->have_context && id <= r->last_context))
    return NANOAMTQ_ERROR_ARGUMENT;
  for (unsigned i = 0; i < r->config.max_contexts; ++i)
    if (!r->contexts[i].state) {
      r->contexts[i] = (relay_context){id, 1, INT64_MAX, CONTEXT_OPENING};
      r->last_context = id;
      r->have_context = 1;
      return NANOAMTQ_OK;
    }
  return NANOAMTQ_ERROR_LIMIT;
}
int nanoamtq_relay_close_context(nanoamtq_relay *r, int64_t now, uint64_t id) {
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  relay_context *c = find_context(r, id);
  if (!c || c->state != CONTEXT_ACTIVE)
    return NANOAMTQ_ERROR_ARGUMENT;
  c->state = CONTEXT_CLOSING;
  return NANOAMTQ_OK;
}
static int data_allowed(const nanoamtq_relay *r, unsigned version, const uint8_t *source, const uint8_t *group) {
  return r->ip_version == version && nanoamt_memberships_allows(r->authorized, version, group, source) &&
         nanoamt_memberships_allows(r->requested, version, group, source) &&
         (!r->pending || nanoamt_memberships_allows(r->pending, version, group, source));
}
static int forwardable(const ip_packet *ip) {
  return address_unicast(ip->source, ip->version) && multicast(ip->destination, ip->version) && ip->ttl &&
         (ip->version == 4 ? !(ip->destination[0] == 224 && !ip->destination[1] && !ip->destination[2])
                           : (ip->destination[1] & 15u) > 2);
}
int nanoamtq_relay_datagram_begin(nanoamtq_relay *r, int64_t now, uint64_t id, const uint8_t *p, size_t n,
                                  nanoamtq_relay_cursor *cursor) {
  if (!cursor || (!p && n))
    return NANOAMTQ_ERROR_ARGUMENT;
  memset(cursor, 0, sizeof(*cursor));
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  relay_context *c = find_context(r, id);
  if (!c)
    return NANOAMTQ_ERROR_ARGUMENT;
  ip_packet ip;
  if (c->state != CONTEXT_ACTIVE || n > NANOAMTQ_MAX_DATA_MESSAGE - 2 || !nanoamt_ip_forward_decode(p, n, &ip) ||
      ip.size != n || !forwardable(&ip) || !data_allowed(r, ip.version, ip.source, ip.destination))
    return NANOAMTQ_IGNORED;
  cursor->owner = r;
  cursor->ip = p;
  cursor->size = n;
  cursor->context_id = id;
  return NANOAMTQ_OK;
}
static void copy_message(uint8_t *out, const uint8_t *ip, size_t offset, size_t count) {
  while (count && offset < 2) {
    *out++ = (uint8_t)(offset ? 0 : MULTICAST_DATA);
    ++offset;
    --count;
  }
  if (count)
    memcpy(out, ip + offset - 2, count);
}
int nanoamtq_relay_datagram_next(nanoamtq_relay *r, int64_t now, nanoamtq_relay_cursor *f, size_t budget,
                                 uint8_t *bytes, size_t capacity, nanoamtq_relay_datagram_output *out) {
  if (out)
    memset(out, 0, sizeof(*out));
  if (!r || !f || f->owner != r || !out || (!bytes && capacity))
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = nanoamtq_relay_tick(r, now);
  if (rc)
    return rc;
  size_t total = f->size + 2;
  if (f->offset == total)
    return NANOAMTQ_OK;
  ip_packet ip;
  relay_context *c = find_context(r, f->context_id);
  if (!c || c->state != CONTEXT_ACTIVE || !nanoamt_ip_forward_decode(f->ip, f->size, &ip) ||
      !data_allowed(r, ip.version, ip.source, ip.destination)) {
    f->offset = total;
    return NANOAMTQ_IGNORED;
  }
  size_t head = 1 + amtq_varint_size(f->context_id), take = total;
  uint8_t format = NANOAMTQ_COMPLETE;
  uint64_t packet_id = 0;
  if (f->packet_id || total + head > budget) {
    format = NANOAMTQ_FRAGMENT;
    packet_id = f->packet_id ? f->packet_id : c->next_packet_id;
    if (packet_id > AMTQ_VARINT_MAX)
      return protocol(r, NANOAMTQ_CLOSE_CONTEXT);
    head += amtq_varint_size(packet_id) + amtq_varint_size(total) + amtq_varint_size(f->offset);
    if (budget <= head) {
      out->size = head + 1;
      return NANOAMTQ_ERROR_BUFFER;
    }
    take = total - f->offset;
    if (take > budget - head)
      take = budget - head;
  }
  out->size = head + take;
  if (capacity < out->size)
    return NANOAMTQ_ERROR_BUFFER;
  size_t at = amtq_put(bytes, format);
  at += amtq_put(bytes + at, f->context_id);
  if (format == NANOAMTQ_FRAGMENT) {
    at += amtq_put(bytes + at, packet_id);
    at += amtq_put(bytes + at, total);
    at += amtq_put(bytes + at, f->offset);
  }
  copy_message(bytes + at, f->ip, f->offset, take);
  out->connection_id = r->config.connection_id;
  out->context_id = f->context_id;
  out->packet_id = packet_id;
  out->offset = f->offset;
  out->total_size = total;
  out->format = format;
  out->ip_version = ip.version;
  memcpy(out->source, ip.source, ip_address_size(ip.version));
  memcpy(out->group, ip.destination, ip_address_size(ip.version));
  if (format == NANOAMTQ_FRAGMENT && !f->packet_id) {
    f->packet_id = packet_id;
    ++c->next_packet_id;
  }
  f->offset += take;
  return NANOAMTQ_PACKET;
}
int nanoamtq_relay_datagram_valid(nanoamtq_relay *r, int64_t now, const nanoamtq_relay_datagram_output *out,
                                  const uint8_t *bytes, size_t size) {
  if (!r || !out || !bytes || out->connection_id != r->config.connection_id || out->size != size ||
      nanoamtq_relay_tick(r, now))
    return 0;
  relay_context *c = find_context(r, out->context_id);
  nanoamtq_datagram d;
  if (!c || c->state != CONTEXT_ACTIVE || !data_allowed(r, out->ip_version, out->source, out->group) ||
      nanoamtq_datagram_decode(bytes, size, &d) || d.context_id != out->context_id || d.format != out->format)
    return 0;
  if (d.format == NANOAMTQ_COMPLETE) {
    ip_packet ip;
    return d.size == out->total_size && !out->packet_id && !out->offset && d.size >= 3 && d.data[0] == MULTICAST_DATA &&
           !d.data[1] && nanoamt_ip_forward_decode(d.data + 2, d.size - 2, &ip) && ip.size == d.size - 2 &&
           ip.version == out->ip_version && forwardable(&ip) &&
           !memcmp(ip.source, out->source, ip_address_size(ip.version)) &&
           !memcmp(ip.destination, out->group, ip_address_size(ip.version));
  }
  return d.format == NANOAMTQ_FRAGMENT && d.packet_id == out->packet_id && d.offset == out->offset &&
         d.total_size == out->total_size;
}
