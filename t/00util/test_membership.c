#include "fixtures.h"
#include "nanoamt/membership.h"
#include <limits.h>

static uint8_t group4[16] = {232, 1, 2, 3}, group6[16] = {255, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2};
static uint8_t sources4[3][16] = {{192, 0, 2, 1}, {192, 0, 2, 2}, {192, 0, 2, 3}};
static uint8_t sources6[3][16] = {{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                                  {0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
                                  {0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}};
/* Independent wire builder: tests do not use the production report encoder. */
static size_t report(uint8_t *ip, unsigned version, unsigned type, unsigned mask) {
  memset(ip, 0, 512);
  size_t stride = version == 4 ? 4 : 16, header = version == 4 ? 24 : 48;
  uint8_t *p = ip + header;
  p[0] = (uint8_t)(version == 4 ? 0x22 : 143);
  put16(p + 6, 1);
  p[8] = (uint8_t)type;
  memcpy(p + 12, version == 4 ? group4 : group6, stride);
  unsigned count = 0;
  for (unsigned i = 0; i < 3; ++i)
    if (mask & (1u << i)) {
      memcpy(p + 12 + stride + count * stride, version == 4 ? sources4[i] : sources6[i], stride);
      ++count;
    }
  put16(p + 10, count);
  size_t length = 12 + stride * (1 + count);
  if (version == 4) {
    ip[0] = 0x46;
    put16(ip + 2, (unsigned)(header + length));
    ip[8] = 1;
    ip[9] = 2;
    ip[16] = 224;
    ip[19] = 22;
    ip[20] = 0x94;
    ip[21] = 4;
    ip_checksum(ip);
    put16(p + 2, sum16(p, length));
  } else {
    ip[0] = 0x60;
    put16(ip + 4, (unsigned)(8 + length));
    ip[7] = 1;
    ip[24] = 255;
    ip[25] = 2;
    ip[39] = 22;
    memcpy(ip + 40, (uint8_t[]){58, 0, 5, 2, 0, 0, 1, 0}, 8);
    fixture_checksum6(ip, p, length, 58, 2);
  }
  return header + length;
}
static nanoamt_memberships *state(unsigned mode) {
  nanoamt_membership_config config = {0};
  config.mode = (uint8_t)mode;
  config.membership_interval_ms = 10000;
  config.last_member_time_ms = 2000;
  nanoamt_memberships *s = nanoamt_memberships_new(&config, 0);
  CHECK(s);
  return s;
}
static void update(nanoamt_memberships *s, unsigned v, int64_t now, unsigned type, unsigned mask) {
  uint8_t bytes[512];
  size_t size = report(bytes, v, type, mask);
  CHECK(nanoamt_memberships_apply(s, now, bytes, size, v) == NANOAMT_OK);
}
static unsigned reception(nanoamt_memberships *s, unsigned v) {
  unsigned mask = 0;
  for (unsigned i = 0; i < 3; ++i)
    if (nanoamt_memberships_allows(s, v, v == 4 ? group4 : group6, v == 4 ? sources4[i] : sources6[i]))
      mask |= 1u << i;
  return mask;
}
static void endpoint(void) {
  /* All six records from INCLUDE and EXCLUDE, for both wire families. */
  static const unsigned expect_include[] = {2, 5, 2, 5, 3, 1};
  static const unsigned expect_exclude[] = {2, 5, 2, 5, 6, 4};
  for (unsigned v = 4; v <= 6; v += 2)
    for (unsigned exclude = 0; exclude < 2; ++exclude)
      for (unsigned type = 1; type <= 6; ++type) {
        nanoamt_memberships *s = state(NANOAMT_MEMBERSHIP_ENDPOINT);
        update(s, v, 0, exclude ? 2 : 1, 1);
        update(s, v, 1, type, 2);
        CHECK(reception(s, v) == (exclude ? expect_exclude[type - 1] : expect_include[type - 1]));
        CHECK(nanoamt_memberships_next_timeout(s) == INT64_MAX);
        CHECK(nanoamt_memberships_tick(s, 2000000) == NANOAMT_OK);
        CHECK(reception(s, v) == (exclude ? expect_exclude[type - 1] : expect_include[type - 1]));
        nanoamt_memberships_free(s);
      }
  nanoamt_memberships *s = state(NANOAMT_MEMBERSHIP_ENDPOINT);
  update(s, 4, 0, 2, 0);
  update(s, 4, 1, 3, 0);
  CHECK(nanoamt_memberships_count(s) == 0);
  nanoamt_memberships_free(s);
}
static void router(void) {
  for (unsigned v = 4; v <= 6; v += 2) {
    nanoamt_memberships *s = state(NANOAMT_MEMBERSHIP_ROUTER);
    update(s, v, 0, 1, 1);
    update(s, v, 100, 1, 2);
    CHECK(reception(s, v) == 3); /* IS_IN accumulates router interests. */
    update(s, v, 200, 6, 1);
    CHECK(reception(s, v) == 3); /* BLOCK retains reception through LMQT. */
    CHECK(nanoamt_memberships_next_timeout(s) == 2200);
    CHECK(nanoamt_memberships_tick(s, 2200) == NANOAMT_OK);
    CHECK(reception(s, v) == 2);
    CHECK(nanoamt_memberships_tick(s, 10100) == NANOAMT_OK);
    CHECK(nanoamt_memberships_count(s) == 0);
    update(s, v, 10100, 1, 1);
    update(s, v, 10200, 2, 3); /* EXCLUDE X={1},Y={2}. */
    CHECK(reception(s, v) == 5);
    update(s, v, 10300, 1, 2); /* Source 2 now has a live listener. */
    CHECK(reception(s, v) == 7);
    update(s, v, 10400, 3, 2); /* Lower group timer, preserve included B. */
    CHECK(nanoamt_memberships_tick(s, 12400) == NANOAMT_OK);
    CHECK(reception(s, v) == 2);
    CHECK(nanoamt_memberships_tick(s, 20400) == NANOAMT_OK);
    CHECK(nanoamt_memberships_count(s) == 0);
    nanoamt_memberships_free(s);
  }
  /* Exercise each of the 12 router transition rows against distinct X/Y/A. */
  static const unsigned immediate_in[] = {3, 5, 3, 5, 3, 1};
  static const unsigned immediate_ex[] = {7, 5, 7, 5, 7, 5};
  for (unsigned type = 1; type <= 6; ++type) {
    for (unsigned ex = 0; ex < 2; ++ex) {
      nanoamt_memberships *s = state(0);
      update(s, 4, 0, 1, 1);
      if (ex)
        update(s, 4, 0, 2, 3);
      update(s, 4, 100, type, 2);
      CHECK(reception(s, 4) == (ex ? immediate_ex[type - 1] : immediate_in[type - 1]));
      nanoamt_memberships_free(s);
    }
  }
}
static void algebra(void) {
  for (unsigned v = 4; v <= 6; v += 2)
    for (unsigned ea = 0; ea < 2; ++ea)
      for (unsigned eb = 0; eb < 2; ++eb)
        for (unsigned ma = 0; ma < 8; ++ma)
          for (unsigned mb = 0; mb < 8; ++mb) {
            nanoamt_memberships *a = state(1), *b = state(1), *u = NULL, *i = NULL;
            update(a, v, 0, ea ? 2 : 1, ma);
            update(b, v, 0, eb ? 2 : 1, mb);
            unsigned pa = ea ? 7 ^ ma : ma, pb = eb ? 7 ^ mb : mb;
            CHECK(!nanoamt_memberships_union(a, b, &u));
            CHECK(!nanoamt_memberships_intersection(a, b, &i));
            CHECK(reception(u, v) == (pa | pb));
            CHECK(reception(i, v) == (pa & pb));
            /* An EXCLUDE filter always includes sources outside our test set. */
            int subset = (!ea || eb) && ((pa & pb) == pa);
            CHECK(nanoamt_memberships_subset(a, b) == subset);
            CHECK(nanoamt_memberships_subset(i, a));
            CHECK(nanoamt_memberships_subset(i, b));
            nanoamt_memberships_free(a);
            nanoamt_memberships_free(b);
            nanoamt_memberships_free(u);
            nanoamt_memberships_free(i);
          }
}
static void validation(void) {
  uint8_t bytes[512], before[16][16];
  nanoamt_membership_config config = {0};
  config.mode = 1;
  config.max_sources = config.max_sources_per_group = 1;
  nanoamt_memberships *s = nanoamt_memberships_new(&config, 0);
  CHECK(s);
  update(s, 4, 0, 1, 1);
  size_t n = report(bytes, 4, 1, 3);
  CHECK(nanoamt_memberships_apply(s, 1, bytes, n, 4) == NANOAMT_RELAY_ERROR_LIMIT);
  CHECK(reception(s, 4) == 1);
  n = report(bytes, 4, 1, 2);
  for (size_t i = 0; i < n; ++i) {
    uint8_t saved = bytes[i];
    bytes[i] ^= 0x80;
    CHECK(nanoamt_memberships_apply(s, 1, bytes, n, 4) == NANOAMT_IGNORED);
    CHECK(reception(s, 4) == 1);
    bytes[i] = saved;
  }
  for (size_t i = 0; i < n; ++i)
    CHECK(nanoamt_memberships_apply(s, 1, bytes, i, 4) == NANOAMT_IGNORED);
  /* Auxiliary data is checksummed and skipped as part of the record. */
  bytes[33] = 1;
  memcpy(bytes + n, (uint8_t[]){1, 2, 3, 4}, 4);
  n += 4;
  put16(bytes + 2, (unsigned)n);
  put16(bytes + 26, 0);
  put16(bytes + 26, sum16(bytes + 24, n - 24));
  ip_checksum(bytes);
  CHECK(!nanoamt_memberships_apply(s, 1, bytes, n, 4));
  CHECK(reception(s, 4) == 2);
  update(s, 4, 1, 1, 1);
  nanoamt_membership_filter filter;
  CHECK(nanoamt_memberships_get(s, 0, &filter, NULL, 0) == NANOAMT_RELAY_ERROR_BUFFER);
  CHECK(filter.source_count == 1);
  CHECK(!nanoamt_memberships_get(s, 0, &filter, before, 16));
  CHECK(!memcmp(before[0], sources4[0], 16));
  CHECK(nanoamt_memberships_tick(s, -1) == NANOAMT_ERROR_ARGUMENT);
  CHECK(nanoamt_memberships_tick(s, INT64_MAX) == NANOAMT_ERROR_ARGUMENT);
  nanoamt_memberships_free(s);
  memset(&config, 0, sizeof(config));
  config.max_sources = 1; /* Default per-group limit fits the total limit. */
  s = nanoamt_memberships_new(&config, 0);
  CHECK(s);
  nanoamt_memberships_free(s);
  /* A valid first record followed by a truncated second must not commit. */
  s = state(1);
  n = report(bytes, 4, 2, 0);
  put16(bytes + 30, 2);
  put16(bytes + 26, 0);
  put16(bytes + 26, sum16(bytes + 24, n - 24));
  CHECK(nanoamt_memberships_apply(s, 0, bytes, n, 4) == NANOAMT_IGNORED);
  CHECK(!nanoamt_memberships_count(s));
  nanoamt_memberships_free(s);
}
static void legacy(void) {
  for (unsigned v = 4; v <= 6; v += 2) {
    uint8_t bytes[512];
    nanoamt_memberships *s = state(0);
    report(bytes, v, 2, 0);
    size_t header = v == 4 ? 24 : 48, length = v == 4 ? 8 : 24;
    uint8_t *p = bytes + header;
    memset(p, 0, length);
    p[0] = (uint8_t)(v == 4 ? 0x16 : 131);
    memcpy(p + (v == 4 ? 4 : 8), v == 4 ? group4 : group6, v == 4 ? 4 : 16);
    memcpy(bytes + (v == 4 ? 16 : 24), v == 4 ? group4 : group6, v == 4 ? 4 : 16);
    if (v == 4) {
      put16(bytes + 2, (unsigned)(header + length));
      ip_checksum(bytes);
      put16(p + 2, sum16(p, length));
    } else {
      put16(bytes + 4, (unsigned)(8 + length));
      fixture_checksum6(bytes, p, length, 58, 2);
    }
    CHECK(!nanoamt_memberships_apply(s, 0, bytes, header + length, v));
    CHECK(reception(s, v) == 7);
    update(s, v, 100, 6, 1); /* Legacy group ignores modern BLOCK. */
    CHECK(nanoamt_memberships_tick(s, 2200) == NANOAMT_OK);
    CHECK(reception(s, v) == 7);
    CHECK(nanoamt_memberships_tick(s, 10000) == NANOAMT_OK);
    CHECK(!nanoamt_memberships_count(s));
    CHECK(!nanoamt_memberships_apply(s, 10000, bytes, header + length, v));
    CHECK(reception(s, v) == 7);
    p[0] = (uint8_t)(v == 4 ? 0x17 : 132);
    memset(bytes + (v == 4 ? 16 : 24), 0, v == 4 ? 4 : 16);
    if (v == 4) {
      bytes[16] = 224;
      bytes[19] = 2;
      put16(p + 2, 0);
      put16(p + 2, sum16(p, length));
      ip_checksum(bytes);
    } else {
      bytes[24] = 255;
      bytes[25] = 2;
      bytes[39] = 2;
      fixture_checksum6(bytes, p, length, 58, 2);
    }
    CHECK(!nanoamt_memberships_apply(s, 10001, bytes, header + length, v));
    CHECK(reception(s, v) == 7);
    CHECK(!nanoamt_memberships_tick(s, 12001));
    CHECK(!nanoamt_memberships_count(s));
    nanoamt_memberships_free(s);
  }
}
static void capacity(void) {
  for (unsigned mode = 0; mode < 2; ++mode) {
    nanoamt_membership_config config = {0};
    config.mode = (uint8_t)mode;
    config.max_groups = 1;
    config.max_sources = config.max_sources_per_group = 1;
    nanoamt_memberships *s = nanoamt_memberships_new(&config, 0);
    CHECK(s);
    update(s, 4, 0, 1, 1);
    uint8_t bytes[512];
    size_t n = report(bytes, 4, 1, 2);
    bytes[39]++;  /* First record adds a distinct group beyond capacity. */
    bytes[n] = 3; /* Second record withdraws the original group. */
    memset(bytes + n + 1, 0, 7);
    memcpy(bytes + n + 4, group4, 4);
    n += 8;
    put16(bytes + 2, (unsigned)n);
    put16(bytes + 30, 2);
    put16(bytes + 26, 0);
    put16(bytes + 26, sum16(bytes + 24, n - 24));
    ip_checksum(bytes);
    int limited = 0;
    CHECK(!nanoamt_memberships_apply_limited(s, 1, bytes, n, 4, &limited));
    CHECK(limited);
    if (mode == 0) {
      CHECK(reception(s, 4) == 1);
      CHECK(!nanoamt_memberships_tick(s, 2001));
    }
    CHECK(!nanoamt_memberships_count(s));
    nanoamt_memberships_free(s);
    s = nanoamt_memberships_new(&config, 0);
    CHECK(s);
    update(s, 4, 0, 1, 1);
    /* A malformed later record still rolls back the WHOLE report. */
    put16(bytes + n - 6, 1); /* Claims a source absent from the final record. */
    put16(bytes + 26, 0);
    put16(bytes + 26, sum16(bytes + 24, n - 24));
    CHECK(nanoamt_memberships_apply_limited(s, 1, bytes, n, 4, &limited) == NANOAMT_IGNORED);
    CHECK(!limited && reception(s, 4) == 1);
    nanoamt_memberships_free(s);
  }
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "endpoint"))
    endpoint();
  else if (!strcmp(argv[1], "router"))
    router();
  else if (!strcmp(argv[1], "algebra"))
    algebra();
  else if (!strcmp(argv[1], "validation"))
    validation();
  else if (!strcmp(argv[1], "legacy"))
    legacy();
  else if (!strcmp(argv[1], "capacity"))
    capacity();
  else
    CHECK(0);
  printf("===AMT membership %s OK===\n", argv[1]);
  return 0;
}
