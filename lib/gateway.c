#include "internal.h"
#include <limits.h>
#include <stdlib.h>

typedef struct session {
  nanoamt_endpoint relay;
  uint8_t mac[6], nonce[4], endpoint[18];
  int has_endpoint;
} session;

struct nanoamt {
  nanoamt_config config;
  nanoamt_state state;
  nanoamt_endpoint relay;
  uint8_t nonce[4];
  session session, query, teardown;
  nanoamt_reassembly *reassembly;
  int64_t last_now, deadline, refresh_at, report_at;
  unsigned attempts, discoveries, robustness, repeats;
  int joined, error;
};

static int64_t after(int64_t now, uint32_t delay) {
  return now > INT64_MAX - delay ? INT64_MAX : now + delay;
}

static int advance_time(nanoamt *g, int64_t now) {
  if (now < g->last_now || now == INT64_MAX)
    return 0;
  g->last_now = now;
  return 1;
}

static int fail(nanoamt *g, int error) {
  g->state = NANOAMT_STATE_FAILED;
  g->joined = 0;
  return g->error = error;
}

static int random_bytes(nanoamt *g, void *out, size_t size) {
  return g->config.random_bytes(g->config.random_context, out, size);
}

static int random_delay(nanoamt *g, uint32_t low, uint32_t high, uint32_t *delay) {
  uint32_t random;
  if (random_bytes(g, &random, sizeof(random)) != 0)
    return NANOAMT_ERROR_RANDOM;
  *delay = low + random % (high - low + 1);
  return NANOAMT_OK;
}

static void schedule_teardown(nanoamt *g) {
  if (g->joined && g->session.has_endpoint)
    g->teardown = g->session;
}

static void discover(nanoamt *g, int64_t now) {
  schedule_teardown(g);
  g->state = g->config.direct ? NANOAMT_STATE_REQUESTING : NANOAMT_STATE_DISCOVERING;
  if (g->config.direct)
    g->relay = g->config.discovery;
  g->joined = 0;
  g->attempts = g->repeats = 0;
  g->deadline = now;
  g->refresh_at = g->report_at = INT64_MAX;
  ++g->discoveries;
}

nanoamt *nanoamt_new(const nanoamt_config *config, int64_t now) {
  if (!config || !config->random_bytes || now < 0 || now == INT64_MAX)
    return NULL;
  nanoamt_config c = *config;
  c.ip_version = (uint8_t)ip_version(c.ip_version);
  c.discovery.ip_version = (uint8_t)ip_version(c.discovery.ip_version);
  if ((c.discovery.ip_version != 4 && c.discovery.ip_version != 6) || (c.ip_version != 4 && c.ip_version != 6) ||
      !address_unicast(c.discovery.ip, c.discovery.ip_version) || !c.discovery.port ||
      (!c.any_source && !address_unicast(c.source, c.ip_version)) || !multicast(c.group, c.ip_version) ||
      c.max_attempts > 16 || c.max_discoveries > 16)
    return NULL;
  nanoamt *g = calloc(1, sizeof(*g));
  if (!g)
    return NULL;
  g->reassembly = nanoamt_reassembly_create();
  if (!g->reassembly) {
    free(g);
    return NULL;
  }
  g->config = c;
  if (!g->config.max_attempts)
    g->config.max_attempts = 3;
  if (!g->config.max_discoveries)
    g->config.max_discoveries = 2;
  if (!g->config.refresh_cap_ms)
    g->config.refresh_cap_ms = 60000;
  g->last_now = now;
  g->robustness = 2;
  discover(g, now);
  return g;
}

void nanoamt_free(nanoamt *g) {
  if (g)
    nanoamt_reassembly_destroy(g->reassembly);
  free(g);
}
nanoamt_state nanoamt_get_state(const nanoamt *g) {
  return g ? g->state : NANOAMT_STATE_CLOSED;
}

int nanoamt_is_joined(const nanoamt *g) {
  return g && g->joined && !g->teardown.has_endpoint;
}

int64_t nanoamt_next_timeout(const nanoamt *g) {
  if (!g || g->state == NANOAMT_STATE_CLOSED || g->state == NANOAMT_STATE_FAILED)
    return INT64_MAX;
  if (g->teardown.has_endpoint)
    return g->last_now;
  if (g->state != NANOAMT_STATE_JOINED)
    return g->deadline;
  int64_t next = g->refresh_at;
  if (g->repeats && g->report_at < next)
    next = g->report_at;
  return next;
}

static int emit_report(nanoamt *g, nanoamt_datagram *out, enum report_type type) {
  out->destination = g->session.relay;
  nanoamt_report_encode(out, &g->config, g->session.mac, g->session.nonce, type);
  return NANOAMT_PACKET;
}

static int emit_teardown(const session *s, nanoamt_datagram *out) {
  out->destination = s->relay;
  out->size = 30;
  memset(out->bytes, 0, 30);
  out->bytes[0] = TEARDOWN;
  memcpy(out->bytes + 2, s->mac, 6);
  memcpy(out->bytes + 8, s->nonce, 4);
  memcpy(out->bytes + 12, s->endpoint, 18);
  return NANOAMT_PACKET;
}

int nanoamt_send(nanoamt *g, int64_t now, nanoamt_datagram *out) {
  if (!g || !out || !advance_time(g, now))
    return NANOAMT_ERROR_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (g->state == NANOAMT_STATE_FAILED)
    return g->error;
  if (g->state == NANOAMT_STATE_CLOSED || now < nanoamt_next_timeout(g))
    return NANOAMT_OK;

  if (g->teardown.has_endpoint) {
    g->teardown.has_endpoint = 0;
    if (g->state == NANOAMT_STATE_REPORTING)
      g->joined = 0;
    return emit_teardown(&g->teardown, out);
  }
  uint32_t delay;
  if (g->state == NANOAMT_STATE_LEAVING) {
    if (!g->repeats) {
      g->state = NANOAMT_STATE_CLOSED;
      return NANOAMT_OK;
    }
    if (random_delay(g, 1, 1000, &delay) < 0)
      return fail(g, NANOAMT_ERROR_RANDOM);
    --g->repeats;
    g->deadline = after(now, delay);
    if (g->session.has_endpoint)
      return emit_teardown(&g->session, out);
    return emit_report(g, out, REPORT_LEAVE);
  }
  if (g->state == NANOAMT_STATE_REPORTING) {
    if (!g->joined) {
      if (random_delay(g, 1, 1000, &delay) < 0)
        return fail(g, NANOAMT_ERROR_RANDOM);
      g->repeats = g->robustness;
      g->report_at = after(now, delay);
    }
    g->session = g->query;
    g->joined = 1;
    g->state = NANOAMT_STATE_JOINED;
    return emit_report(g, out, REPORT_CURRENT);
  }
  if (g->state == NANOAMT_STATE_JOINED) {
    if (g->repeats && now >= g->report_at) {
      if (random_delay(g, 1, 1000, &delay) < 0)
        return fail(g, NANOAMT_ERROR_RANDOM);
      --g->repeats;
      g->report_at = after(now, delay);
      return emit_report(g, out, REPORT_JOIN);
    }
    g->state = NANOAMT_STATE_REQUESTING;
    g->attempts = 0;
    g->deadline = now;
  }
  if (g->attempts == g->config.max_attempts) {
    if (g->discoveries >= g->config.max_discoveries)
      return fail(g, NANOAMT_ERROR_TIMEOUT);
    discover(g, now);
    if (g->teardown.has_endpoint) {
      g->teardown.has_endpoint = 0;
      return emit_teardown(&g->teardown, out);
    }
  }
  if (!g->attempts) {
    if (random_bytes(g, g->nonce, sizeof(g->nonce)) != 0)
      return fail(g, NANOAMT_ERROR_RANDOM);
    /* RFC 7450: nonzero nonce */
    if (g->state == NANOAMT_STATE_DISCOVERING) {
      unsigned retry = 0;
      while (zero(g->nonce, sizeof(g->nonce))) {
        if (++retry == 8)
          return fail(g, NANOAMT_ERROR_RANDOM);
        if (random_bytes(g, g->nonce, sizeof(g->nonce)) != 0)
          return fail(g, NANOAMT_ERROR_RANDOM);
      }
    }
  }
  uint32_t high = g->attempts < 7 ? (1000u << g->attempts) : 120000;
  if (high > 120000)
    high = 120000;
  if (random_delay(g, 1000, high, &delay) < 0)
    return fail(g, NANOAMT_ERROR_RANDOM);
  out->destination = g->state == NANOAMT_STATE_DISCOVERING ? g->config.discovery : g->relay;
  out->size = 8;
  out->bytes[0] = g->state == NANOAMT_STATE_DISCOVERING ? RELAY_DISCOVERY : RELAY_REQUEST;
  if (g->state == NANOAMT_STATE_REQUESTING && g->config.ip_version == 6)
    out->bytes[1] = 1;
  if (g->state == NANOAMT_STATE_REQUESTING && g->config.ecn)
    out->bytes[1] |= 2;
  memcpy(out->bytes + 4, g->nonce, 4);
  ++g->attempts;
  g->deadline = after(now, delay);
  return NANOAMT_PACKET;
}

int nanoamt_receive(nanoamt *g, int64_t now, const nanoamt_endpoint *sender, uint8_t *p, size_t size,
                    nanoamt_packet *packet) {
  return nanoamt_receive_ecn(g, now, sender, p, size, -1, packet);
}

int nanoamt_receive_ecn(nanoamt *g, int64_t now, const nanoamt_endpoint *sender, uint8_t *p, size_t size, int outer_ecn,
                        nanoamt_packet *packet) {
  if (packet)
    memset(packet, 0, sizeof(*packet));
  if (!g || !sender || !p || !packet || outer_ecn < -1 || outer_ecn > 3 || !advance_time(g, now))
    return NANOAMT_ERROR_ARGUMENT;
  if (size < 2 || g->state == NANOAMT_STATE_FAILED || g->state == NANOAMT_STATE_CLOSED ||
      g->state == NANOAMT_STATE_LEAVING)
    return NANOAMT_IGNORED;
  if (p[0] == RELAY_ADVERTISEMENT) {
    if (g->state != NANOAMT_STATE_DISCOVERING || !g->attempts || size != 8 + ip_address_size(sender->ip_version) ||
        !endpoint_equal(sender, &g->config.discovery) || memcmp(p + 4, g->nonce, 4) ||
        !address_unicast(p + 8, sender->ip_version))
      return NANOAMT_IGNORED;
    g->relay = g->config.discovery;
    memcpy(g->relay.ip, p + 8, ip_address_size(sender->ip_version));
    g->state = NANOAMT_STATE_REQUESTING;
    g->attempts = 0;
    g->deadline = now;
    return NANOAMT_OK;
  }
  if (!endpoint_equal(sender, &g->relay))
    return NANOAMT_IGNORED;
  if (p[0] == MEMBERSHIP_QUERY) {
    size_t tail = (p[1] & 1) ? 18 : 0;
    uint32_t interval;
    unsigned robustness;
    if (g->state != NANOAMT_STATE_REQUESTING || !g->attempts || size < 12 + tail || memcmp(p + 8, g->nonce, 4) ||
        !nanoamt_query_decode(p + 12, size - 12 - tail, g->config.ip_version, &interval, &robustness))
      return NANOAMT_IGNORED;
    int changed = tail && g->session.has_endpoint && memcmp(g->session.endpoint, p + size - tail, 18);
    if (changed)
      schedule_teardown(g);
    /* L flag */
    if ((p[1] & 2) && (!g->joined || changed)) {
      if (g->discoveries >= g->config.max_discoveries)
        return fail(g, NANOAMT_ERROR_TIMEOUT);
      discover(g, now);
      g->deadline = after(now, 1000);
      return NANOAMT_OK;
    }
    memset(&g->query, 0, sizeof(g->query));
    g->query.relay = g->relay;
    memcpy(g->query.mac, p + 2, 6);
    memcpy(g->query.nonce, p + 8, 4);
    g->query.has_endpoint = tail != 0;
    if (tail)
      memcpy(g->query.endpoint, p + size - tail, 18);
    g->robustness = robustness;
    g->discoveries = 0;
    if (interval > g->config.refresh_cap_ms)
      interval = g->config.refresh_cap_ms;
    g->refresh_at = after(now, interval);
    g->deadline = now;
    g->state = NANOAMT_STATE_REPORTING;
    return NANOAMT_OK;
  }
  if (p[0] == MULTICAST_DATA && g->joined) {
    uint8_t *inner = p + 2;
    size_t length = size - 2, address_size = ip_address_size(g->config.ip_version);
    size_t source_offset = g->config.ip_version == 6 ? 8 : 12;
    if (length < source_offset + 2 * address_size || inner[0] >> 4 != g->config.ip_version ||
        memcmp(inner + source_offset + address_size, g->config.group, address_size) ||
        (!g->config.any_source && memcmp(inner + source_offset, g->config.source, address_size)))
      return NANOAMT_IGNORED;
    if (g->config.ecn) {
      if (outer_ecn < 0)
        return NANOAMT_ERROR_ARGUMENT;
      if (!nanoamt_ecn_decapsulate(inner, length, (unsigned)outer_ecn))
        return NANOAMT_IGNORED;
    }
    if (nanoamt_reassemble(g->reassembly, now, &inner, &length) &&
        nanoamt_udp_decode(inner, length, &g->config, packet))
      return NANOAMT_PACKET;
  }
  return NANOAMT_IGNORED;
}

int nanoamt_leave(nanoamt *g, int64_t now) {
  if (!g || !advance_time(g, now))
    return NANOAMT_ERROR_ARGUMENT;
  if (g->state == NANOAMT_STATE_LEAVING || g->state == NANOAMT_STATE_CLOSED)
    return NANOAMT_OK;
  g->state = g->joined ? NANOAMT_STATE_LEAVING : NANOAMT_STATE_CLOSED;
  g->joined = 0;
  g->repeats = g->robustness;
  g->deadline = now;
  return NANOAMT_OK;
}
