#include "fixtures.h"
#include <limits.h>

static nanoamt *requesting(nanoamt_config *config, nanoamt_datagram *request) {
  nanoamt *g = nanoamt_new(config, 0);
  CHECK(g);
  nanoamt_datagram discovery;
  CHECK(nanoamt_send(g, 0, &discovery) == NANOAMT_PACKET);
  CHECK(discovery.size == 8 && discovery.bytes[0] == 1);
  uint8_t p[128];
  nanoamt_packet packet;
  fixture_advertisement(p, &discovery, &config->discovery);
  CHECK(nanoamt_receive(g, 1, &config->discovery, p, 12, &packet) == NANOAMT_OK);
  CHECK(nanoamt_send(g, 1, request) == NANOAMT_PACKET && request->bytes[0] == 3);
  CHECK(memcmp(request->bytes + 4, discovery.bytes + 4, 4) != 0);
  return g;
}

static void join(nanoamt *g, nanoamt_config *config, nanoamt_datagram *request) {
  uint8_t p[128];
  nanoamt_packet packet;
  nanoamt_datagram report;
  size_t n = fixture_query(p, request, 125, 0);
  CHECK(nanoamt_receive(g, 2, &config->discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_REPORTING);
  CHECK(!nanoamt_is_joined(g));
  CHECK(nanoamt_send(g, 2, &report) == NANOAMT_PACKET);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_JOINED);
  CHECK(report.size == 56 && report.bytes[0] == 5);
  CHECK(memcmp(report.bytes + 2, "COOKIE", 6) == 0);
  CHECK(memcmp(report.bytes + 8, request->bytes + 4, 4) == 0);
  CHECK(report.bytes[12] == 0x46 && report.bytes[20] == 1 && report.bytes[21] == 2);
  CHECK(report.bytes[32] == 0x94 && report.bytes[33] == 4);
  CHECK(sum16(report.bytes + 12, 24) == 0 && sum16(report.bytes + 36, 20) == 0);
  CHECK(report.bytes[44] == 1 && report.bytes[46] == 0 && report.bytes[47] == 1);
  CHECK(memcmp(report.bytes + 48, config->group, 4) == 0);
  CHECK(memcmp(report.bytes + 52, config->source, 4) == 0);
}

static void test_lifecycle(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  nanoamt_datagram req, out;
  nanoamt *g = requesting(&c, &req);
  join(g, &c, &req);
  for (int i = 0; i < 2; ++i) {
    int64_t due = nanoamt_next_timeout(g);
    CHECK(due > 2 && due <= 2002);
    CHECK(nanoamt_send(g, due - 1, &out) == NANOAMT_OK);
    CHECK(nanoamt_send(g, due, &out) == NANOAMT_PACKET && out.bytes[44] == 5);
  }
  CHECK(nanoamt_next_timeout(g) == 60002);
  CHECK(nanoamt_send(g, 60002, &out) == NANOAMT_PACKET && out.bytes[0] == 3);
  CHECK(memcmp(out.bytes + 4, req.bytes + 4, 4) != 0);
  uint8_t p[128];
  nanoamt_packet packet;
  size_t n = fixture_data(p, &c, 1, 1);
  CHECK(nanoamt_receive(g, 60003, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
  n = fixture_query(p, &req, 1, 0);
  CHECK(nanoamt_receive(g, 60003, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  n = fixture_query(p, &out, 10, 1);
  CHECK(nanoamt_receive(g, 60003, &c.discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_REPORTING);
  CHECK(nanoamt_is_joined(g));
  n = fixture_data(p, &c, 1, 1);
  CHECK(nanoamt_receive(g, 60003, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
  CHECK(nanoamt_send(g, 60003, &out) == NANOAMT_PACKET && out.bytes[44] == 1);
  CHECK(nanoamt_next_timeout(g) == 70003);
  CHECK(nanoamt_leave(g, 60004) == NANOAMT_OK);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_LEAVING);
  for (int i = 0; i < 2; ++i) {
    CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_PACKET);
    CHECK(out.size == 30 && out.bytes[0] == 7);
  }
  CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_OK);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_CLOSED);
  CHECK(nanoamt_next_timeout(g) == INT64_MAX);
  nanoamt_free(g);
}

static void test_data(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  nanoamt_datagram req;
  nanoamt *g = requesting(&c, &req);
  join(g, &c, &req);
  uint8_t p[128], good[128];
  nanoamt_packet packet;
  for (int options = 0; options < 2; ++options)
    for (int check = 0; check < 2; ++check) {
      size_t n = fixture_data(good, &c, options, check);
      for (size_t size = 0; size < n; ++size) {
        memcpy(p, good, sizeof(p));
        CHECK(nanoamt_receive(g, 3, &c.discovery, p, size, &packet) == NANOAMT_IGNORED);
        CHECK(packet.data == NULL);
      }
      memcpy(p, good, sizeof(p));
      CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
      CHECK(packet.size == 5 && memcmp(packet.data, "\x40\x00\x80\xff\x01", 5) == 0);
      CHECK(packet.ttl == 42 && packet.tos == 0x2c);
      CHECK(packet.source.port == 1234 && packet.destination.port == 5000);
      CHECK(memcmp(packet.source.ip, c.source, 4) == 0);
      packet.data[0] = 7;
      CHECK(p[n - 5] == 7);
    }
  size_t n = fixture_data(good, &c, 1, 1);
  const size_t bad_fields[] = {0, 2, 4, 8, 11, 12, 14, 18, 23, 28, 30, 32, 36};
  for (size_t i = 0; i < sizeof(bad_fields) / sizeof(*bad_fields); ++i) {
    memcpy(p, good, sizeof(p));
    p[bad_fields[i]] ^= 1;
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  }
  const size_t changes[] = {8, 9, 14, 18};
  for (size_t i = 0; i < sizeof(changes) / sizeof(*changes); ++i) {
    memcpy(p, good, sizeof(p));
    p[changes[i]] ^= 1;
    ip_checksum(p + 2);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  }
  nanoamt_endpoint foreign = c.discovery;
  foreign.port++;
  CHECK(nanoamt_receive(g, 3, &foreign, good, n, &packet) == NANOAMT_IGNORED);
  foreign = c.discovery;
  foreign.ip[3]++;
  CHECK(nanoamt_receive(g, 3, &foreign, good, n, &packet) == NANOAMT_IGNORED);
  good[1] = 255;
  CHECK(nanoamt_receive(g, 3, &c.discovery, good, n, &packet) == NANOAMT_PACKET);
  n = fixture_data(good, &c, 1, 1);
  memmove(good + 26, good + 22, n - 22);
  memset(good + 22, 1, 4);
  n += 4;
  good[2] = 0x47;
  put16(good + 4, (unsigned)n - 2);
  ip_checksum(good + 2);
  CHECK(nanoamt_receive(g, 3, &c.discovery, good, n, &packet) == NANOAMT_PACKET);
  const uint8_t lengths[] = {0, 1, 5, 255};
  for (size_t i = 0; i < sizeof(lengths); ++i) {
    memcpy(p, good, n);
    p[27] = lengths[i];
    ip_checksum(p + 2);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  }
  nanoamt_free(g);
}

static void test_control_validation(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  nanoamt_datagram req;
  nanoamt *g = requesting(&c, &req);
  uint8_t good[128], p[128];
  nanoamt_packet packet;
  size_t n = fixture_query(good, &req, 125, 1);
  for (size_t i = 0; i < n; ++i)
    CHECK(nanoamt_receive(g, 2, &c.discovery, good, i, &packet) == NANOAMT_IGNORED);
  size_t changes[] = {0, 8, 12, 20, 21, 28, 36, 40, 46};
  for (size_t i = 0; i < sizeof(changes) / sizeof(*changes); ++i) {
    memcpy(p, good, n);
    p[changes[i]] ^= 1;
    CHECK(nanoamt_receive(g, 2, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  }
  nanoamt_endpoint wrong = c.discovery;
  wrong.port++;
  CHECK(nanoamt_receive(g, 2, &wrong, good, n, &packet) == NANOAMT_IGNORED);
  memcpy(p, good, n);
  p[40] = 232;
  p[38] = p[39] = 0;
  put16(p + 38, sum16(p + 36, 12));
  CHECK(nanoamt_receive(g, 2, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  good[1] |= 2;
  CHECK(nanoamt_receive(g, 2, &c.discovery, good, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_DISCOVERING);
  CHECK(nanoamt_next_timeout(g) == 1002);
  nanoamt_free(g);
}

static int broken_random(void *ctx, void *out, size_t n) {
  (void)ctx;
  (void)out;
  (void)n;
  return -1;
}

static int zero_random(void *ctx, void *out, size_t n) {
  (void)ctx;
  memset(out, 0, n);
  return 0;
}

static int fallible_random(void *ctx, void *out, size_t n) {
  if (*(unsigned *)ctx == UINT_MAX)
    return 1;
  return fixture_random(ctx, out, n);
}

static void test_random_failure(void) {
  for (unsigned stage = 0; stage < 4; ++stage) {
    unsigned random = 0;
    nanoamt_config c = fixture_config(&random);
    c.random_bytes = fallible_random;
    nanoamt_datagram req, out;
    nanoamt_packet packet;
    uint8_t p[128];
    nanoamt *g = requesting(&c, &req);
    if (stage) {
      join(g, &c, &req);
      CHECK(nanoamt_is_joined(g));
    } else {
      size_t n = fixture_query(p, &req, 125, 0);
      CHECK(nanoamt_receive(g, 2, &c.discovery, p, n, &packet) == NANOAMT_OK);
    }
    if (stage == 2)
      for (unsigned i = 0; i < 2; ++i)
        CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_PACKET);
    if (stage == 3)
      CHECK(nanoamt_leave(g, 2) == NANOAMT_OK);
    random = UINT_MAX;
    int64_t now = nanoamt_next_timeout(g);
    CHECK(nanoamt_send(g, now, &out) == NANOAMT_ERROR_RANDOM);
    CHECK(!out.size && !nanoamt_is_joined(g));
    CHECK(nanoamt_get_state(g) == NANOAMT_STATE_FAILED);
    CHECK(nanoamt_next_timeout(g) == INT64_MAX);
    CHECK(nanoamt_send(g, now, &out) == NANOAMT_ERROR_RANDOM);
    size_t n = fixture_data(p, &c, 0, 1);
    CHECK(nanoamt_receive(g, now, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    nanoamt_free(g);
  }
}

static void test_retry_and_config(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  nanoamt *g = nanoamt_new(&c, 0);
  nanoamt_datagram out, first;
  CHECK(nanoamt_send(g, 0, &first) == NANOAMT_PACKET);
  CHECK(nanoamt_send(g, 999, &out) == NANOAMT_OK);
  CHECK(nanoamt_send(g, 998, &out) == NANOAMT_ERROR_ARGUMENT);
  CHECK(nanoamt_send(g, 1000, &out) == NANOAMT_PACKET);
  CHECK(memcmp(first.bytes, out.bytes, 8) == 0);
  int calls = 0, ret;
  do {
    ret = nanoamt_send(g, nanoamt_next_timeout(g), &out);
    CHECK(++calls < 10);
  } while (ret >= 0);
  CHECK(ret == NANOAMT_ERROR_TIMEOUT && nanoamt_get_state(g) == NANOAMT_STATE_FAILED);
  nanoamt_free(g);
  c.random_bytes = broken_random;
  g = nanoamt_new(&c, 0);
  CHECK(nanoamt_send(g, 0, &out) == NANOAMT_ERROR_RANDOM);
  CHECK(nanoamt_send(g, 1, &out) == NANOAMT_ERROR_RANDOM);
  nanoamt_free(g);
  c.random_bytes = zero_random;
  g = nanoamt_new(&c, 0);
  CHECK(nanoamt_send(g, 0, &out) == NANOAMT_ERROR_RANDOM);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_FAILED);
  nanoamt_free(g);
  c.random_bytes = fixture_random;
  random = 255;
  g = nanoamt_new(&c, 0);
  CHECK(nanoamt_send(g, 0, &out) == NANOAMT_PACKET && out.bytes[4] == 1);
  nanoamt_free(g);
  CHECK(nanoamt_new(&c, -1) == NULL);
  c.group[0] = 223;
  CHECK(nanoamt_new(&c, 0) == NULL);
  c.group[0] = 232;
  c.source[0] = 224;
  CHECK(nanoamt_new(&c, 0) == NULL);
  c.source[0] = 192;
  c.max_attempts = 17;
  CHECK(nanoamt_new(&c, 0) == NULL);
  c.max_attempts = 0;
  c.ip_version = 5;
  CHECK(nanoamt_new(&c, 0) == NULL);
  c.ip_version = 0;
  c.port = 5000;
  g = requesting(&c, &out);
  for (unsigned i = 1; i < c.max_attempts || i < 3; ++i)
    CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_PACKET && out.bytes[0] == 3);
  CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_PACKET && out.bytes[0] == 1);
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_DISCOVERING);
  nanoamt_free(g);
}

static void test_discovery_and_qqic(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  nanoamt_datagram out;
  nanoamt *g = nanoamt_new(&c, 0);
  CHECK(nanoamt_send(g, 0, &out) == NANOAMT_PACKET);
  nanoamt_endpoint relay = {{198, 51, 100, 8}, NANOAMT_PORT};
  uint8_t p[128];
  nanoamt_packet packet;
  fixture_advertisement(p, &out, &relay);
  CHECK(nanoamt_receive(g, 1, &relay, p, 12, &packet) == NANOAMT_IGNORED);
  p[4] ^= 1;
  CHECK(nanoamt_receive(g, 1, &c.discovery, p, 12, &packet) == NANOAMT_IGNORED);
  p[4] ^= 1;
  CHECK(nanoamt_receive(g, 1, &c.discovery, p, 11, &packet) == NANOAMT_IGNORED);
  CHECK(nanoamt_receive(g, 1, &c.discovery, p, 12, &packet) == NANOAMT_OK);
  CHECK(nanoamt_send(g, 1, &out) == NANOAMT_PACKET);
  CHECK(memcmp(out.destination.ip, relay.ip, 4) == 0);
  nanoamt_free(g);
  c.refresh_cap_ms = 10000000;
  g = requesting(&c, &out);
  size_t n = fixture_query(p, &out, 0x96, 0);
  CHECK(nanoamt_receive(g, 2, &c.discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_send(g, 2, &out) == NANOAMT_PACKET);
  for (int i = 0; i < 2; ++i)
    CHECK(nanoamt_send(g, nanoamt_next_timeout(g), &out) == NANOAMT_PACKET);
  CHECK(nanoamt_next_timeout(g) == 352002);
  nanoamt_free(g);
}

static void test_ipv4_defaults(void) {
  for (unsigned inner = 0; inner <= 4; inner += 4)
    for (unsigned outer = 0; outer <= 4; outer += 4) {
      unsigned random = 0;
      nanoamt_config c = fixture_config(&random);
      c.ip_version = (uint8_t)inner;
      c.discovery.ip_version = (uint8_t)outer;
      nanoamt_datagram req;
      nanoamt *g = requesting(&c, &req);
      CHECK(c.ip_version == inner && c.discovery.ip_version == outer);
      CHECK(req.destination.ip_version == 4);
      join(g, &c, &req);
      for (unsigned sender = 0; sender <= 4; sender += 4) {
        nanoamt_endpoint peer = c.discovery;
        peer.ip_version = (uint8_t)sender;
        uint8_t p[128];
        nanoamt_packet packet;
        size_t n = fixture_data(p, &c, 0, 1);
        CHECK(nanoamt_receive(g, 3, &peer, p, n, &packet) == NANOAMT_PACKET);
        CHECK(packet.source.ip_version == 4 && packet.destination.ip_version == 4);
      }
      nanoamt_free(g);
    }
}

int main(int argc, char **argv) {
  static const struct {
    const char *name;
    void (*run)(void);
  } cases[] = {{"lifecycle", test_lifecycle},        {"data", test_data},
               {"control", test_control_validation}, {"retry", test_retry_and_config},
               {"random", test_random_failure},      {"discovery", test_discovery_and_qqic},
               {"defaults", test_ipv4_defaults}};
  if (argc > 2)
    return 2;
  int matched = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    if (argc == 2 && strcmp(argv[1], cases[i].name) != 0)
      continue;
    cases[i].run();
    printf("===AMT GATEWAY %s OK===\n", cases[i].name);
    matched = 1;
  }
  return matched ? 0 : 2;
}
