#include "nanoamt/membership.h"
#include "internal.h"
#include <limits.h>
#include <stdlib.h>

typedef struct member_source {
  uint8_t address[16];
  int64_t until;
} member_source;
typedef struct member_group {
  uint8_t address[16], version, exclude;
  int64_t until, legacy_until;
  member_source *sources;
  size_t count, capacity;
} member_group;
struct nanoamt_memberships {
  nanoamt_membership_config config;
  member_group *groups;
  size_t count, sources;
  int64_t now;
};

static int64_t deadline(int64_t now, uint32_t delay) {
  return now > INT64_MAX - delay ? INT64_MAX : now + delay;
}
static member_group *find_group(const nanoamt_memberships *s, unsigned version, const uint8_t *group) {
  for (size_t i = 0; i < s->count; ++i)
    if (s->groups[i].version == version && !memcmp(s->groups[i].address, group, ip_address_size(version)))
      return s->groups + i;
  return NULL;
}
static member_source *find_source(const member_group *g, const uint8_t *source) {
  for (size_t i = 0; i < g->count; ++i)
    if (!memcmp(g->sources[i].address, source, ip_address_size(g->version)))
      return g->sources + i;
  return NULL;
}
static void remove_source(nanoamt_memberships *s, member_group *g, size_t i) {
  g->sources[i] = g->sources[--g->count];
  --s->sources;
}
static void remove_group(nanoamt_memberships *s, size_t i) {
  s->sources -= s->groups[i].count;
  free(s->groups[i].sources);
  s->groups[i] = s->groups[--s->count];
  memset(s->groups + s->count, 0, sizeof(*s->groups));
}
static int add_source(nanoamt_memberships *s, member_group *g, const uint8_t *address, int64_t until) {
  member_source *p = find_source(g, address);
  if (p) {
    p->until = until;
    return NANOAMT_OK;
  }
  if (g->count == s->config.max_sources_per_group || s->sources == s->config.max_sources)
    return NANOAMT_RELAY_ERROR_LIMIT;
  if (g->count == g->capacity) {
    size_t capacity = g->capacity ? g->capacity * 2 : 4;
    if (capacity > s->config.max_sources_per_group)
      capacity = s->config.max_sources_per_group;
    p = realloc(g->sources, capacity * sizeof(*p));
    if (!p)
      return NANOAMT_RELAY_ERROR_MEMORY;
    g->sources = p;
    g->capacity = capacity;
  }
  p = g->sources + g->count++;
  memset(p, 0, sizeof(*p));
  memcpy(p->address, address, ip_address_size(g->version));
  p->until = until;
  ++s->sources;
  return NANOAMT_OK;
}
static member_group *add_group(nanoamt_memberships *s, unsigned version, const uint8_t *address) {
  member_group *g = find_group(s, version, address);
  if (g)
    return g;
  if (s->count == s->config.max_groups)
    return NULL;
  g = s->groups + s->count++;
  memset(g, 0, sizeof(*g));
  g->version = (uint8_t)version;
  memcpy(g->address, address, ip_address_size(version));
  return g;
}

nanoamt_memberships *nanoamt_memberships_new(const nanoamt_membership_config *config, int64_t now) {
  nanoamt_membership_config c = {0};
  if (config)
    c = *config;
  if (now < 0 || now == INT64_MAX || c.mode > NANOAMT_MEMBERSHIP_ENDPOINT)
    return NULL;
  if (!c.max_groups)
    c.max_groups = 64;
  if (!c.max_sources)
    c.max_sources = 1024;
  if (!c.max_sources_per_group)
    c.max_sources_per_group = c.max_sources < 64 ? c.max_sources : 64;
  if (!c.max_report_records)
    c.max_report_records = 1024;
  if (!c.membership_interval_ms)
    c.membership_interval_ms = 260000;
  if (!c.last_member_time_ms)
    c.last_member_time_ms = 2000;
  if (c.max_groups > 8192 || c.max_sources > 65535 || c.max_sources_per_group > 65535 ||
      c.max_sources_per_group > c.max_sources || c.max_report_records > 8192 ||
      c.last_member_time_ms > c.membership_interval_ms)
    return NULL;
  nanoamt_memberships *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  s->groups = calloc(c.max_groups, sizeof(*s->groups));
  if (!s->groups) {
    free(s);
    return NULL;
  }
  s->config = c;
  s->now = now;
  return s;
}
void nanoamt_memberships_free(nanoamt_memberships *s) {
  if (s) {
    for (size_t i = 0; i < s->count; ++i)
      free(s->groups[i].sources);
    free(s->groups);
    free(s);
  }
}
nanoamt_memberships *nanoamt_memberships_clone(const nanoamt_memberships *s) {
  if (!s)
    return NULL;
  nanoamt_memberships *copy = nanoamt_memberships_new(&s->config, s->now);
  if (!copy)
    return NULL;
  for (size_t i = 0; i < s->count; ++i) {
    member_group *g = copy->groups + i;
    *g = s->groups[i];
    g->sources = NULL;
    g->capacity = g->count;
    ++copy->count;
    if (g->count) {
      g->sources = malloc(g->count * sizeof(*g->sources));
      if (!g->sources) {
        nanoamt_memberships_free(copy);
        return NULL;
      }
      memcpy(g->sources, s->groups[i].sources, g->count * sizeof(*g->sources));
    }
  }
  copy->sources = s->sources;
  return copy;
}

int nanoamt_memberships_tick(nanoamt_memberships *s, int64_t now) {
  if (!s || now < s->now || now == INT64_MAX)
    return NANOAMT_ERROR_ARGUMENT;
  s->now = now;
  if (s->config.mode == NANOAMT_MEMBERSHIP_ENDPOINT)
    return NANOAMT_OK;
  for (size_t i = 0; i < s->count;) {
    member_group *g = s->groups + i;
    if (g->exclude && g->until <= now)
      g->exclude = 0;
    for (size_t j = 0; j < g->count;)
      if (!g->exclude && g->sources[j].until <= now)
        remove_source(s, g, j);
      else
        ++j;
    if (!g->exclude && !g->count)
      remove_group(s, i);
    else
      ++i;
  }
  return NANOAMT_OK;
}
int64_t nanoamt_memberships_next_timeout(const nanoamt_memberships *s) {
  int64_t next = INT64_MAX;
  if (!s || s->config.mode == NANOAMT_MEMBERSHIP_ENDPOINT)
    return next;
  for (size_t i = 0; i < s->count; ++i) {
    const member_group *g = s->groups + i;
    if (g->exclude && g->until < next)
      next = g->until;
    if (g->legacy_until > s->now && g->legacy_until < next)
      next = g->legacy_until;
    for (size_t j = 0; j < g->count; ++j)
      if (g->sources[j].until > s->now && g->sources[j].until < next)
        next = g->sources[j].until;
  }
  return next;
}
int nanoamt_memberships_allows(const nanoamt_memberships *s, unsigned version, const uint8_t *group,
                               const uint8_t *source) {
  if (!s || !group || !source || (version != 4 && version != 6))
    return 0;
  const member_group *g = find_group(s, version, group);
  if (!g)
    return 0;
  const member_source *p = find_source(g, source);
  if (g->exclude && g->until > s->now)
    return !p || p->until > s->now;
  return p && p->until > s->now;
}
size_t nanoamt_memberships_count(const nanoamt_memberships *s) {
  return s ? s->count : 0;
}
static int listed(const uint8_t *list, size_t count, size_t stride, const uint8_t *address) {
  for (size_t i = 0; i < count; ++i)
    if (!memcmp(list + i * stride, address, stride))
      return 1;
  return 0;
}

static int apply_endpoint(nanoamt_memberships *s, member_group *g, unsigned type, const uint8_t *list, size_t count) {
  size_t stride = ip_address_size(g->version);
  if (type <= 4) {
    s->sources -= g->count;
    g->count = 0;
    g->exclude = (uint8_t)(type == 2 || type == 4);
    g->until = INT64_MAX;
    for (size_t i = 0; i < count; ++i) {
      int rc = add_source(s, g, list + i * stride, g->exclude ? 0 : INT64_MAX);
      if (rc)
        return rc;
    }
  } else if ((type == 5 && !g->exclude) || (type == 6 && g->exclude)) {
    for (size_t i = 0; i < count; ++i) {
      int rc = add_source(s, g, list + i * stride, g->exclude ? 0 : INT64_MAX);
      if (rc)
        return rc;
    }
  } else {
    for (size_t i = 0; i < g->count;)
      if (listed(list, count, stride, g->sources[i].address))
        remove_source(s, g, i);
      else
        ++i;
  }
  return NANOAMT_OK;
}
static void shorten(int64_t *timer, int64_t until) {
  if (*timer > until)
    *timer = until;
}
static int apply_router(nanoamt_memberships *s, member_group *g, unsigned type, const uint8_t *list, size_t count) {
  size_t stride = ip_address_size(g->version);
  int64_t gmi = deadline(s->now, s->config.membership_interval_ms);
  int64_t lmqt = deadline(s->now, s->config.last_member_time_ms);
  if (g->legacy_until > s->now) {
    if (type == 6)
      return NANOAMT_OK;
    if (type == 4)
      count = 0;
  }
  /* RFC 3376 6.4 and RFC 3810 7.4. AMT suppresses generated queries,
   * retaining their source/group timer actions for bounded leave latency. */
  if (type == 1 || type == 3 || type == 5) {
    if (type == 3) {
      for (size_t i = 0; i < g->count; ++i)
        if (g->sources[i].until > s->now && !listed(list, count, stride, g->sources[i].address))
          shorten(&g->sources[i].until, lmqt);
      if (g->exclude)
        shorten(&g->until, lmqt);
    }
    for (size_t i = 0; i < count; ++i) {
      int rc = add_source(s, g, list + i * stride, gmi);
      if (rc)
        return rc;
    }
  } else if (type == 2 || type == 4) {
    int old_exclude = g->exclude;
    int64_t old_timer = g->until;
    for (size_t i = 0; i < g->count;)
      if (!listed(list, count, stride, g->sources[i].address))
        remove_source(s, g, i);
      else
        ++i;
    for (size_t i = 0; i < count; ++i) {
      member_source *p = find_source(g, list + i * stride);
      if (!p) {
        int64_t timer = old_exclude ? (type == 2 ? gmi : old_timer) : 0;
        int rc = add_source(s, g, list + i * stride, timer);
        if (rc)
          return rc;
        p = find_source(g, list + i * stride);
      }
      if (type == 4 && p->until > s->now)
        shorten(&p->until, lmqt);
    }
    g->exclude = 1;
    g->until = gmi;
  } else {
    for (size_t i = 0; i < count; ++i) {
      member_source *p = find_source(g, list + i * stride);
      if (!p && g->exclude) {
        int rc = add_source(s, g, list + i * stride, g->until);
        if (rc)
          return rc;
        p = find_source(g, list + i * stride);
      }
      if (p && p->until > s->now)
        shorten(&p->until, lmqt);
    }
  }
  return NANOAMT_OK;
}
static int apply_record(nanoamt_memberships *s, unsigned version, const uint8_t *group, unsigned type,
                        const uint8_t *list, size_t count, int legacy) {
  if (type < 1 || type > 6)
    return NANOAMT_OK; /* Unknown group records are skipped, not applied. */
  if (!multicast(group, version))
    return NANOAMT_IGNORED;
  size_t stride = ip_address_size(version);
  for (size_t i = 0; i < count; ++i)
    if (!address_unicast(list + i * stride, version))
      return NANOAMT_IGNORED;
  if (count > s->config.max_sources_per_group || count > s->config.max_sources)
    return NANOAMT_RELAY_ERROR_LIMIT;
  member_group *g = find_group(s, version, group);
  if (!g && !count && (type == 1 || type == 3 || type == 5 || type == 6))
    return NANOAMT_OK;
  if (!g && !(g = add_group(s, version, group)))
    return NANOAMT_RELAY_ERROR_LIMIT;
  if (legacy && type == 2)
    g->legacy_until = deadline(s->now, s->config.membership_interval_ms);
  int rc = s->config.mode == NANOAMT_MEMBERSHIP_ENDPOINT ? apply_endpoint(s, g, type, list, count)
                                                         : apply_router(s, g, type, list, count);
  if (!rc && !g->exclude && !g->count)
    remove_group(s, (size_t)(g - s->groups));
  return rc;
}
static void restrict_record(nanoamt_memberships *s, unsigned version, const uint8_t *address, unsigned type,
                            const uint8_t *list, size_t count) {
  member_group *g = find_group(s, version, address);
  if (!g)
    return; /* No room for a new group: ignore additions. */
  size_t stride = ip_address_size(version);
  int router = s->config.mode == NANOAMT_MEMBERSHIP_ROUTER;
  int64_t lmqt = deadline(s->now, s->config.last_member_time_ms);
  if (router && g->legacy_until > s->now) {
    if (type == 6)
      return;
    if (type == 4)
      count = 0;
  }
  if (type == 1 || type == 3 || type == 5) {
    if (!router && type != 5) {
      if (g->exclude) {
        /* Converting an unbounded EXCLUDE set to an oversized INCLUDE list
         * cannot fit the configured representation; deny the entire group. */
        remove_group(s, (size_t)(g - s->groups));
        return;
      }
      for (size_t i = 0; i < g->count;)
        if (!listed(list, count, stride, g->sources[i].address))
          remove_source(s, g, i);
        else
          ++i;
    } else if (router) {
      for (size_t i = 0; i < g->count; ++i) {
        member_source *p = g->sources + i;
        if (p->until <= s->now)
          continue;
        if (listed(list, count, stride, p->address))
          p->until = deadline(s->now, s->config.membership_interval_ms);
        else if (type == 3)
          shorten(&p->until, lmqt);
      }
      if (type == 3 && g->exclude)
        shorten(&g->until, lmqt);
    }
  } else if (type == 2 || type == 4 || type == 6) {
    if (!g->exclude) {
      for (size_t i = 0; i < g->count;)
        if (listed(list, count, stride, g->sources[i].address)) {
          if (router && type == 6) {
            shorten(&g->sources[i].until, lmqt);
            ++i;
          } else
            remove_source(s, g, i);
        } else
          ++i;
    } else {
      for (size_t i = 0; i < count; ++i) {
        member_source *p = find_source(g, list + i * stride);
        if (p) {
          if (router && p->until > s->now && (type == 4 || type == 6))
            shorten(&p->until, lmqt);
          else if (!router)
            p->until = 0;
        } else {
          int64_t until = router && type == 6 ? (g->until < lmqt ? g->until : lmqt) : 0;
          if (add_source(s, g, list + i * stride, until)) {
            /* Unknown blocked sources cannot be represented safely. */
            remove_group(s, (size_t)(g - s->groups));
            return;
          }
        }
      }
    }
  }
  if (!g->exclude && !g->count)
    remove_group(s, (size_t)(g - s->groups));
}
static int attempt_record(nanoamt_memberships *s, unsigned version, const uint8_t *group, unsigned type,
                          const uint8_t *list, size_t count, int legacy, int *limited) {
  if (!limited)
    return apply_record(s, version, group, type, list, count, legacy);
  nanoamt_memberships *trial = nanoamt_memberships_clone(s);
  if (!trial)
    return NANOAMT_RELAY_ERROR_MEMORY;
  int rc = apply_record(trial, version, group, type, list, count, legacy);
  if (!rc) {
    nanoamt_memberships old = *s;
    *s = *trial;
    *trial = old;
  } else if (rc == NANOAMT_RELAY_ERROR_LIMIT) {
    *limited = 1;
    restrict_record(s, version, group, type, list, count);
    rc = NANOAMT_OK;
  }
  nanoamt_memberships_free(trial);
  return rc;
}
static int parse_report(nanoamt_memberships *s, const uint8_t *bytes, size_t size, unsigned version, int *limited) {
  ip_packet ip;
  if (!nanoamt_ip_decode((uint8_t *)bytes, size, &ip) || ip.version != version || ip.ttl != 1 || !ip.router_alert)
    return NANOAMT_IGNORED;
  const uint8_t *p = ip.payload;
  size_t n = ip.payload_size, stride = ip_address_size(version);
  if (n < 8 || ip.protocol != (version == 4 ? 2 : 58) ||
      nanoamt_checksum(p, n, version == 4 ? 0 : nanoamt_pseudo_sum(&ip, 58, n)))
    return NANOAMT_IGNORED;
  if (version == 4 && (p[0] == 0x16 || p[0] == 0x17)) {
    static const uint8_t routers[] = {224, 0, 0, 2};
    if (n != 8 || p[1] || memcmp(ip.destination, p[0] == 0x16 ? p + 4 : routers, 4))
      return NANOAMT_IGNORED;
    return attempt_record(s, version, p + 4, p[0] == 0x16 ? 2 : 3, NULL, 0, 1, limited);
  }
  if (version == 6 && (p[0] == 131 || p[0] == 132)) {
    static const uint8_t routers[16] = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    if (n != 24 || p[1] || memcmp(ip.destination, p[0] == 131 ? p + 8 : routers, 16))
      return NANOAMT_IGNORED;
    return attempt_record(s, version, p + 8, p[0] == 131 ? 2 : 3, NULL, 0, 1, limited);
  }
  static const uint8_t igmp_destination[4] = {224, 0, 0, 22};
  static const uint8_t mld_destination[16] = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22};
  if (p[0] != (version == 4 ? 0x22 : 143) || p[1] ||
      memcmp(ip.destination, version == 4 ? igmp_destination : mld_destination, stride))
    return NANOAMT_IGNORED;
  size_t records = read16(p + 6), at = 8;
  if (records > s->config.max_report_records)
    return NANOAMT_RELAY_ERROR_LIMIT;
  for (size_t i = 0; i < records; ++i) {
    if (n - at < 4 + stride)
      return NANOAMT_IGNORED;
    size_t sources = read16(p + at + 2), aux = (size_t)p[at + 1] * 4;
    size_t length = 4 + stride + sources * stride + aux;
    if (length > n - at)
      return NANOAMT_IGNORED;
    int rc = attempt_record(s, version, p + at + 4, p[at], p + at + 4 + stride, sources, 0, limited);
    if (rc)
      return rc;
    at += length;
  }
  return at == n ? NANOAMT_OK : NANOAMT_IGNORED;
}
static int apply(nanoamt_memberships *s, int64_t now, const uint8_t *bytes, size_t size, unsigned version,
                 int *limited) {
  if (!s || (!bytes && size) || now < s->now || now == INT64_MAX || (version != 4 && version != 6))
    return NANOAMT_ERROR_ARGUMENT;
  nanoamt_memberships *candidate = nanoamt_memberships_clone(s);
  if (!candidate)
    return NANOAMT_RELAY_ERROR_MEMORY;
  nanoamt_memberships_tick(candidate, now);
  int denied = 0;
  int rc = parse_report(candidate, bytes, size, version, limited ? &denied : NULL);
  if (!rc) {
    nanoamt_memberships old = *s;
    *s = *candidate;
    *candidate = old;
  }
  nanoamt_memberships_free(candidate);
  if (limited)
    *limited = !rc && denied;
  return rc;
}
int nanoamt_memberships_apply(nanoamt_memberships *s, int64_t now, const uint8_t *bytes, size_t size,
                              unsigned version) {
  return apply(s, now, bytes, size, version, NULL);
}
int nanoamt_memberships_apply_limited(nanoamt_memberships *s, int64_t now, const uint8_t *bytes, size_t size,
                                      unsigned version, int *limited) {
  if (!limited)
    return NANOAMT_ERROR_ARGUMENT;
  *limited = 0;
  return apply(s, now, bytes, size, version, limited);
}

static int canonical_source(const nanoamt_memberships *s, const member_group *g, const member_source *p) {
  return g->exclude ? p->until <= s->now : p->until > s->now;
}
int nanoamt_memberships_get(const nanoamt_memberships *s, size_t index, nanoamt_membership_filter *filter,
                            uint8_t (*sources)[16], size_t capacity) {
  if (!s || !filter || index >= s->count || (!sources && capacity))
    return NANOAMT_ERROR_ARGUMENT;
  const member_group *g = s->groups + index;
  memset(filter, 0, sizeof(*filter));
  memcpy(filter->group, g->address, 16);
  filter->ip_version = g->version;
  filter->exclude = g->exclude;
  for (size_t i = 0; i < g->count; ++i)
    if (canonical_source(s, g, g->sources + i))
      ++filter->source_count;
  if (filter->source_count > capacity)
    return NANOAMT_RELAY_ERROR_BUFFER;
  size_t at = 0;
  for (size_t i = 0; i < g->count; ++i)
    if (canonical_source(s, g, g->sources + i))
      memcpy(sources[at++], g->sources[i].address, 16);
  return NANOAMT_OK;
}
static int canonical_has(const nanoamt_memberships *s, const member_group *g, const uint8_t *address) {
  const member_source *p = g ? find_source(g, address) : NULL;
  return p && canonical_source(s, g, p);
}
static int combine_group(nanoamt_memberships *out, const nanoamt_memberships *a, const member_group *ga,
                         const nanoamt_memberships *b, const member_group *gb, int intersect) {
  const member_group *base = ga ? ga : gb;
  if (intersect && (!ga || !gb))
    return NANOAMT_OK;
  member_group *g = add_group(out, base->version, base->address);
  if (!g)
    return NANOAMT_RELAY_ERROR_LIMIT;
  int ea = ga && ga->exclude, eb = gb && gb->exclude;
  g->exclude = (uint8_t)(intersect ? ea && eb : ea || eb);
  g->until = INT64_MAX;
  for (unsigned side = 0; side < 2; ++side) {
    const nanoamt_memberships *s = side ? b : a;
    const member_group *input = side ? gb : ga;
    if (!input)
      continue;
    for (size_t i = 0; i < input->count; ++i) {
      const member_source *p = input->sources + i;
      if (!canonical_source(s, input, p))
        continue;
      int ha = canonical_has(a, ga, p->address), hb = canonical_has(b, gb, p->address);
      int allowed_a = ga && (ea ? !ha : ha), allowed_b = gb && (eb ? !hb : hb);
      int allowed = intersect ? allowed_a && allowed_b : allowed_a || allowed_b;
      if (allowed != g->exclude) {
        int rc = add_source(out, g, p->address, g->exclude ? 0 : INT64_MAX);
        if (rc)
          return rc;
      }
    }
  }
  if (!g->exclude && !g->count)
    remove_group(out, (size_t)(g - out->groups));
  return NANOAMT_OK;
}
static int combine(const nanoamt_memberships *a, const nanoamt_memberships *b, int intersect,
                   nanoamt_memberships **output) {
  if (!output)
    return NANOAMT_ERROR_ARGUMENT;
  *output = NULL;
  if (!a || !b || a->now != b->now)
    return NANOAMT_ERROR_ARGUMENT;
  nanoamt_membership_config config = a->config;
  config.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  nanoamt_memberships *out = nanoamt_memberships_new(&config, a->now);
  if (!out)
    return NANOAMT_RELAY_ERROR_MEMORY;
  for (size_t i = 0; i < a->count; ++i) {
    const member_group *ga = a->groups + i;
    int rc = combine_group(out, a, ga, b, find_group(b, ga->version, ga->address), intersect);
    if (rc) {
      nanoamt_memberships_free(out);
      return rc;
    }
  }
  if (!intersect)
    for (size_t i = 0; i < b->count; ++i) {
      const member_group *gb = b->groups + i;
      if (find_group(a, gb->version, gb->address))
        continue;
      int rc = combine_group(out, a, NULL, b, gb, 0);
      if (rc) {
        nanoamt_memberships_free(out);
        return rc;
      }
    }
  *output = out;
  return NANOAMT_OK;
}
int nanoamt_memberships_union(const nanoamt_memberships *a, const nanoamt_memberships *b, nanoamt_memberships **out) {
  return combine(a, b, 0, out);
}
int nanoamt_memberships_intersection(const nanoamt_memberships *a, const nanoamt_memberships *b,
                                     nanoamt_memberships **out) {
  return combine(a, b, 1, out);
}
int nanoamt_memberships_subset(const nanoamt_memberships *a, const nanoamt_memberships *b) {
  if (!a || !b || a->now != b->now)
    return 0;
  for (size_t i = 0; i < a->count; ++i) {
    const member_group *ga = a->groups + i, *gb = find_group(b, ga->version, ga->address);
    if (!gb || (ga->exclude && !gb->exclude))
      return 0;
    if (!ga->exclude) {
      for (size_t j = 0; j < ga->count; ++j)
        if (canonical_source(a, ga, ga->sources + j) &&
            !nanoamt_memberships_allows(b, ga->version, ga->address, ga->sources[j].address))
          return 0;
    } else {
      for (size_t j = 0; j < gb->count; ++j)
        if (canonical_source(b, gb, gb->sources + j) && !canonical_has(a, ga, gb->sources[j].address))
          return 0;
    }
  }
  return 1;
}
