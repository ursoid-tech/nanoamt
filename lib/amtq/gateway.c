#include "internal.h"

typedef struct context {
  uint64_t id;
  int used, acknowledged;
} context;

struct nanoamtq {
  nanoamtq_config config;
  int error;
  uint64_t close_error;
  int local_settings, peer_settings, requesting, queried, dirty, reported, have_context;
  uint8_t nonce[4];
  int64_t now, control_deadline, refresh_at;
  uint64_t last_context;
  context contexts[NANOAMTQ_MAX_CONTEXTS];
  nanoamtq_membership desired[NANOAMTQ_MAX_MEMBERSHIPS], sent[NANOAMTQ_MAX_MEMBERSHIPS];
  size_t desired_count, sent_count;
  uint8_t control[NANOAMTQ_MAX_CONTROL_VALUE + 16];
  size_t control_size, control_target;
  amtq_reassembly fragments;
  nanoamt_reassembly *ip_fragments;
  uint8_t message[NANOAMTQ_MAX_DATA_MESSAGE];
};

static int fail(nanoamtq *g, int error, uint64_t code) {
  g->error = error;
  g->close_error = code;
  return error;
}
static int protocol(nanoamtq *g, uint64_t code) {
  return fail(g, NANOAMTQ_ERROR_PROTOCOL, code);
}
static int advance(nanoamtq *g, int64_t now) {
  if (!g || now < 0 || now < g->now || now == INT64_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  if (g->error)
    return g->error;
  g->now = now;
  amtq_frag_expire(&g->fragments, now);
  if (now >= g->control_deadline)
    return fail(g, NANOAMTQ_ERROR_TIMEOUT, 0);
  return NANOAMTQ_OK;
}
static int forwardable(const uint8_t *group, unsigned version) {
  if (!multicast(group, version))
    return 0;
  if (version == 4)
    return group[0] != 224 || group[1] != 0 || group[2] != 0;
  return (group[1] & 15) > 2;
}
nanoamtq *nanoamtq_new(const nanoamtq_config *config, int64_t now) {
  if (!config || !config->random_bytes || now < 0 || now == INT64_MAX ||
      (config->ip_version && config->ip_version != 4 && config->ip_version != 6) || config->max_incomplete > 64 ||
      config->max_fragment_ranges > AMTQ_MAX_RANGES)
    return NULL;
  nanoamtq *g = calloc(1, sizeof(*g));
  if (!g)
    return NULL;
  g->config = *config;
  g->config.ip_version = (uint8_t)ip_version(config->ip_version);
  if (!g->config.control_timeout_ms)
    g->config.control_timeout_ms = 10000;
  if (!g->config.refresh_cap_ms)
    g->config.refresh_cap_ms = 60000;
  g->fragments.capacity = config->max_incomplete ? config->max_incomplete : 8;
  g->fragments.max_ranges = config->max_fragment_ranges ? config->max_fragment_ranges : AMTQ_MAX_RANGES;
  g->fragments.timeout = config->reassembly_timeout_ms ? config->reassembly_timeout_ms : 5000;
  g->fragments.slots = calloc(g->fragments.capacity, sizeof(*g->fragments.slots));
  g->ip_fragments = nanoamt_reassembly_create();
  if (!g->fragments.slots || !g->ip_fragments) {
    nanoamtq_free(g);
    return NULL;
  }
  g->now = now;
  g->control_deadline = amtq_after(now, g->config.control_timeout_ms);
  g->refresh_at = INT64_MAX;
  return g;
}
void nanoamtq_free(nanoamtq *g) {
  if (!g)
    return;
  if (g->fragments.slots)
    for (unsigned i = 0; i < g->fragments.capacity; ++i)
      amtq_frag_clear(&g->fragments.slots[i]);
  free(g->fragments.slots);
  nanoamt_reassembly_destroy(g->ip_fragments);
  free(g);
}
int nanoamtq_set_memberships(nanoamtq *g, const nanoamtq_membership *m, size_t count) {
  if (!g || (!m && count) || count > NANOAMTQ_MAX_MEMBERSHIPS)
    return NANOAMTQ_ERROR_ARGUMENT;
  if (g->error)
    return g->error;
  for (size_t i = 0; i < count; ++i)
    if (!forwardable(m[i].group, g->config.ip_version) || m[i].any_source > 1 ||
        (!m[i].any_source && !address_unicast(m[i].source, g->config.ip_version)))
      return NANOAMTQ_ERROR_ARGUMENT;
  if (count)
    memcpy(g->desired, m, count * sizeof(*m));
  g->desired_count = count;
  g->dirty = 1;
  return NANOAMTQ_OK;
}
static int emit(nanoamtq *g, nanoamtq_control *out, uint64_t type, const uint8_t *data, size_t size) {
  nanoamtq_record record = {type, data, size};
  if (nanoamtq_record_encode(&record, out->bytes, sizeof(out->bytes), &out->size))
    return protocol(g, NANOAMTQ_CLOSE_INTERNAL);
  return NANOAMTQ_PACKET;
}

static size_t report(nanoamtq *g, uint8_t *p) {
  unsigned version = g->config.ip_version;
  size_t addr = ip_address_size(version), ip_header = version == 6 ? 48 : 24;
  nanoamt_config c = {0};
  c.ip_version = (uint8_t)version;
  c.any_source = 1;
  nanoamt_datagram seed;
  const uint8_t mac[6] = {0};
  nanoamt_report_encode(&seed, &c, mac, g->nonce, REPORT_CURRENT);
  size_t base = 12 + ip_header;
  memcpy(p, seed.bytes, base + 8);
  uint8_t *groups[NANOAMTQ_MAX_MEMBERSHIPS * 2];
  size_t groups_count = 0, at = base + 8;
  for (size_t i = 0; i < g->desired_count + g->sent_count; ++i) {
    uint8_t *group = i < g->desired_count ? g->desired[i].group : g->sent[i - g->desired_count].group;
    size_t j;
    for (j = 0; j < groups_count; ++j)
      if (!memcmp(groups[j], group, addr))
        break;
    if (j != groups_count)
      continue;
    groups[groups_count++] = group;
    int any = 0;
    for (j = 0; j < g->desired_count; ++j)
      if (!memcmp(g->desired[j].group, group, addr) && g->desired[j].any_source)
        any = 1;
    size_t record_at = at;
    memset(p + at, 0, 4);
    p[at] = (uint8_t)(any ? 2 : 1);
    memcpy(p + at + 4, group, addr);
    at += 4 + addr;
    unsigned sources = 0;
    if (!any) {
      for (j = 0; j < g->desired_count; ++j) {
        const nanoamtq_membership *m = &g->desired[j];
        if (memcmp(m->group, group, addr))
          continue;
        size_t k;
        for (k = 0; k < sources; ++k)
          if (!memcmp(p + record_at + 4 + addr + k * addr, m->source, addr))
            break;
        if (k != sources)
          continue;
        memcpy(p + at, m->source, addr);
        at += addr;
        ++sources;
      }
    }
    write16(p + record_at + 2, (uint16_t)sources);
  }
  write16(p + base + 6, (uint16_t)groups_count);
  write16(p + base + 2, 0);
  if (version == 4) {
    write16(p + 14, (uint16_t)(at - 12));
    write16(p + 22, 0);
    write16(p + 22, nanoamt_checksum(p + 12, ip_header, 0));
    write16(p + base + 2, nanoamt_checksum(p + base, at - base, 0));
  } else {
    write16(p + 16, (uint16_t)(at - 52));
    ip_packet view = {0};
    view.version = 6;
    view.source = p + 20;
    view.destination = p + 36;
    write16(p + base + 2, nanoamt_checksum(p + base, at - base, nanoamt_pseudo_sum(&view, 58, at - base)));
  }
  return at;
}
int nanoamtq_send(nanoamtq *g, int64_t now, nanoamtq_control *out) {
  if (!out)
    return NANOAMTQ_ERROR_ARGUMENT;
  out->size = 0;
  int rc = advance(g, now);
  if (rc)
    return rc;
  if (!g->local_settings) {
    const uint8_t settings[] = {0, 1};
    rc = emit(g, out, NANOAMTQ_SETTINGS, settings, sizeof(settings));
    if (rc == NANOAMTQ_PACKET) {
      g->local_settings = 1;
      if (g->peer_settings)
        g->control_deadline = INT64_MAX;
    }
    return rc;
  }
  if (!g->peer_settings)
    return NANOAMTQ_OK;
  for (size_t i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i) {
    context *c = &g->contexts[i];
    if (c->used && !c->acknowledged) {
      uint8_t id[8];
      size_t n = amtq_put(id, c->id);
      rc = emit(g, out, NANOAMTQ_CONTEXT_ACK, id, n);
      if (rc == NANOAMTQ_PACKET)
        c->acknowledged = 1;
      return rc;
    }
  }
  if (g->requesting)
    return NANOAMTQ_OK;
  if (g->queried && g->dirty) {
    uint8_t data[NANOAMTQ_CONTROL_CAPACITY];
    size_t n = report(g, data);
    rc = emit(g, out, NANOAMTQ_AMT_CONTROL, data, n);
    if (rc == NANOAMTQ_PACKET) {
      memcpy(g->sent, g->desired, g->desired_count * sizeof(*g->sent));
      g->sent_count = g->desired_count;
      g->dirty = 0;
      g->reported = 1;
    }
    return rc;
  }
  if (!g->queried || now >= g->refresh_at) {
    uint8_t request[8] = {3, 0, 0, 0};
    request[1] = (uint8_t)(g->config.ip_version == 6);
    if (g->config.random_bytes(g->config.random_context, request + 4, 4))
      return fail(g, NANOAMTQ_ERROR_RANDOM, NANOAMTQ_CLOSE_INTERNAL);
    rc = emit(g, out, NANOAMTQ_AMT_CONTROL, request, sizeof(request));
    if (rc == NANOAMTQ_PACKET) {
      memcpy(g->nonce, request + 4, 4);
      g->requesting = 1;
      g->control_deadline = amtq_after(now, g->config.control_timeout_ms);
    }
    return rc;
  }
  return NANOAMTQ_OK;
}
static int compare_ids(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static int settings(nanoamtq *g, const uint8_t *p, size_t n) {
  if (g->peer_settings || !n)
    return protocol(g, NANOAMTQ_CLOSE_SETTINGS);
  uint64_t *ids = malloc((n / 2 + 1) * sizeof(*ids));
  if (!ids)
    return protocol(g, NANOAMTQ_CLOSE_INTERNAL);
  size_t at = 0, count = 0;
  int valid = 1, modes = 0;
  while (at < n) {
    uint64_t id, value;
    if (!amtq_get(p, n, &at, &id) || !amtq_get(p, n, &at, &value)) {
      valid = 0;
      break;
    }
    ids[count++] = id;
    if (id == 0)
      modes = (value & 1) != 0;
    if (id == 1)
      valid = 0;
  }
  qsort(ids, count, sizeof(*ids), compare_ids);
  for (size_t i = 1; i < count; ++i)
    if (ids[i] == ids[i - 1])
      valid = 0;
  free(ids);
  if (!valid || !modes)
    return protocol(g, NANOAMTQ_CLOSE_SETTINGS);
  g->peer_settings = 1;
  if (g->local_settings)
    g->control_deadline = INT64_MAX;
  return NANOAMTQ_OK;
}
static context *find_context(nanoamtq *g, uint64_t id) {
  for (size_t i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
    if (g->contexts[i].used && g->contexts[i].id == id)
      return &g->contexts[i];
  return NULL;
}
static int handle(nanoamtq *g, uint64_t type, uint8_t *p, size_t n) {
  if (type == NANOAMTQ_SETTINGS)
    return settings(g, p, n);
  if (!g->peer_settings || !g->local_settings)
    return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
  if (type == NANOAMTQ_AMT_CONTROL) {
    uint32_t interval;
    unsigned robustness;
    ip_packet ip;
    if (n < 12 || p[0] != 4 || (p[1] & ~2u) || !zero(p + 2, 6) || !g->requesting || memcmp(p + 8, g->nonce, 4) ||
        !nanoamt_query_decode(p + 12, n - 12, g->config.ip_version, &interval, &robustness) ||
        !nanoamt_ip_decode(p + 12, n - 12, &ip) || ip.size != n - 12 ||
        ip.payload_size != (g->config.ip_version == 6 ? 28u : 12u))
      return protocol(g, NANOAMTQ_CLOSE_AMT_MESSAGE);
    g->requesting = 0;
    g->queried = g->dirty = 1;
    g->control_deadline = INT64_MAX;
    if (interval > g->config.refresh_cap_ms)
      interval = g->config.refresh_cap_ms;
    g->refresh_at = amtq_after(g->now, interval);
    return NANOAMTQ_OK;
  }
  if (type == NANOAMTQ_CONTEXT_ACK)
    return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
  if (type != NANOAMTQ_CONTEXT && type != NANOAMTQ_CONTEXT_CLOSE)
    return NANOAMTQ_OK;
  size_t at = 0;
  uint64_t id, mode;
  if (!amtq_get(p, n, &at, &id))
    return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
  if (type == NANOAMTQ_CONTEXT_CLOSE) {
    context *c = find_context(g, id);
    if (!c || at != n)
      return protocol(g, NANOAMTQ_CLOSE_CONTEXT);
    memset(c, 0, sizeof(*c));
    amtq_frag_discard(&g->fragments, id);
    return NANOAMTQ_OK;
  }
  if (!amtq_get(p, n, &at, &mode) || at != n)
    return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
  if (mode != 0 || (!g->have_context && id != 0) || (g->have_context && id <= g->last_context))
    return protocol(g, NANOAMTQ_CLOSE_CONTEXT);
  for (size_t i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
    if (!g->contexts[i].used) {
      g->contexts[i] = (context){id, 1, 0};
      g->last_context = id;
      g->have_context = 1;
      return NANOAMTQ_OK;
    }
  return protocol(g, NANOAMTQ_CLOSE_EXCESSIVE_LOAD);
}
int nanoamtq_receive_control(nanoamtq *g, int64_t now, uint64_t stream, const uint8_t *p, size_t n, int fin) {
  if (!p && n)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = advance(g, now);
  if (rc)
    return rc;
  if (stream || fin)
    return protocol(g, NANOAMTQ_CLOSE_CONTROL_STREAM);
  while (n) {
    if (!g->control_target) {
      g->control[g->control_size++] = *p++;
      --n;
      uint64_t type;
      size_t len, header;
      rc = amtq_header(g->control, g->control_size, &type, &len, &header);
      if (rc == NANOAMTQ_INCOMPLETE)
        continue;
      if (rc)
        return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
      g->control_target = header + len;
    }
    size_t take = g->control_target - g->control_size;
    if (take > n)
      take = n;
    if (take)
      memcpy(g->control + g->control_size, p, take);
    g->control_size += take;
    p += take;
    n -= take;
    if (g->control_size == g->control_target) {
      nanoamtq_record r;
      size_t consumed;
      rc = nanoamtq_record_decode(g->control, g->control_size, &r, &consumed);
      if (rc)
        return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
      rc = handle(g, r.type, g->control + consumed - r.size, r.size);
      g->control_size = g->control_target = 0;
      if (rc)
        return rc;
    }
  }
  return NANOAMTQ_OK;
}
static int requested(nanoamtq *g, const ip_packet *ip) {
  size_t addr = ip_address_size(g->config.ip_version);
  for (size_t i = 0; i < g->sent_count; ++i)
    if (!memcmp(g->sent[i].group, ip->destination, addr) &&
        (g->sent[i].any_source || !memcmp(g->sent[i].source, ip->source, addr)))
      return 1;
  return 0;
}
int nanoamtq_receive_datagram(nanoamtq *g, int64_t now, const uint8_t *p, size_t n, nanoamt_packet *packet) {
  if (packet)
    memset(packet, 0, sizeof(*packet));
  if (!packet || (!p && n))
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc = advance(g, now);
  if (rc)
    return rc;
  nanoamtq_datagram d;
  if (nanoamtq_datagram_decode(p, n, &d))
    return protocol(g, NANOAMTQ_CLOSE_PROTOCOL);
  if (d.format != NANOAMTQ_COMPLETE && d.format != NANOAMTQ_FRAGMENT)
    return NANOAMTQ_IGNORED;
  context *c = find_context(g, d.context_id);
  if (!c || !c->acknowledged || !g->reported)
    return NANOAMTQ_IGNORED;
  size_t size = d.size;
  if (d.format == NANOAMTQ_FRAGMENT) {
    rc = amtq_frag_push(&g->fragments, now, &d, g->message);
    if (rc != NANOAMTQ_PACKET)
      return rc;
    size = d.total_size;
  } else
    memmove(g->message, d.data, d.size);
  if (size < 3 || g->message[0] != 6 || g->message[1] != 0)
    return NANOAMTQ_IGNORED;
  uint8_t *ip_bytes = g->message + 2;
  size -= 2;
  if ((ip_bytes[0] >> 4 == 4 && (size < 20 || read16(ip_bytes + 2) != size)) ||
      (ip_bytes[0] >> 4 == 6 && (size < 40 || 40u + read16(ip_bytes + 4) != size)))
    return NANOAMTQ_IGNORED;
  if (!nanoamt_reassemble(g->ip_fragments, now, &ip_bytes, &size))
    return NANOAMTQ_IGNORED;
  ip_packet ip;
  if (!nanoamt_ip_decode(ip_bytes, size, &ip) || ip.version != g->config.ip_version || !requested(g, &ip))
    return NANOAMTQ_IGNORED;
  for (size_t i = 0; i < g->desired_count; ++i) {
    nanoamt_config filter = {0};
    filter.ip_version = g->config.ip_version;
    filter.any_source = g->desired[i].any_source;
    filter.port = g->desired[i].port;
    memcpy(filter.source, g->desired[i].source, 16);
    memcpy(filter.group, g->desired[i].group, 16);
    if (nanoamt_udp_decode(ip_bytes, size, &filter, packet))
      return NANOAMTQ_PACKET;
  }
  return NANOAMTQ_IGNORED;
}
int64_t nanoamtq_next_timeout(const nanoamtq *g) {
  if (!g || g->error)
    return INT64_MAX;
  if (!g->local_settings)
    return g->now;
  int64_t next = g->control_deadline;
  if (g->peer_settings) {
    for (size_t i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
      if (g->contexts[i].used && !g->contexts[i].acknowledged)
        return g->now;
    if (!g->requesting) {
      if (!g->queried || g->dirty)
        return g->now;
      if (g->refresh_at < next)
        next = g->refresh_at;
    }
  }
  int64_t fragments = amtq_frag_deadline(&g->fragments);
  return fragments < next ? fragments : next;
}
int nanoamtq_is_ready(const nanoamtq *g) {
  if (!g || g->error || !g->reported)
    return 0;
  for (size_t i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
    if (g->contexts[i].used && g->contexts[i].acknowledged)
      return 1;
  return 0;
}
int nanoamtq_error(const nanoamtq *g) {
  return g ? g->error : NANOAMTQ_ERROR_ARGUMENT;
}
uint64_t nanoamtq_close_error(const nanoamtq *g) {
  return g ? g->close_error : 0;
}
