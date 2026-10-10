#include "fixtures.h"

static nanoamt *start(const nanoamt_config *c, nanoamt_datagram *request, nanoamt_datagram *report, unsigned flags) {
  uint8_t p[256];
  nanoamt_packet packet;
  nanoamt *g = nanoamt_new(c, 0);
  CHECK(g);
  CHECK(nanoamt_send(g, 0, request) == NANOAMT_PACKET);
  if (!c->direct) {
    size_t n = fixture_advertisement(p, request, &c->discovery);
    CHECK(nanoamt_receive(g, 1, &c->discovery, p, n, &packet) == NANOAMT_OK);
    CHECK(nanoamt_send(g, 1, request) == NANOAMT_PACKET);
  }
  CHECK(request->bytes[0] == 3 && request->bytes[1] == ((c->ip_version == 6) | (c->ecn ? 2 : 0)));
  size_t n = fixture_dual_query(p, request, c, 125, flags);
  CHECK(nanoamt_receive(g, 2, &c->discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(!nanoamt_is_joined(g));
  CHECK(nanoamt_send(g, 2, report) == NANOAMT_PACKET && report->bytes[0] == 5);
  CHECK(nanoamt_is_joined(g));
  return g;
}

static void dual_stack(void) {
  for (int outer = 0; outer < 2; ++outer)
    for (int inner = 0; inner < 2; ++inner)
      for (int asm_mode = 0; asm_mode < 2; ++asm_mode) {
        unsigned random = 0;
        nanoamt_config c = fixture_dual_config(&random, outer, inner, asm_mode);
        nanoamt_datagram request, report;
        nanoamt_packet packet;
        uint8_t p[256];
        nanoamt *g = start(&c, &request, &report, 1);
        size_t offset = inner ? 60 : 36, report_size = (inner ? 28u : 16u) + (asm_mode ? 0u : inner ? 16u : 4u);
        CHECK(report.size == offset + report_size);
        CHECK(report.bytes[offset] == (inner ? 143 : 0x22));
        CHECK(report.bytes[offset + 8] == (asm_mode ? 2 : 1));
        CHECK(report.bytes[offset + 11] == !asm_mode);
        if (inner) {
          uint8_t copy[128];
          memcpy(copy, report.bytes, report.size);
          fixture_checksum6(copy + 12, copy + 60, report_size, 58, 2);
          CHECK(!memcmp(copy, report.bytes, report.size));
        } else
          CHECK(sum16(report.bytes + offset, report_size) == 0);
        for (int options = 0; options < 2; ++options)
          for (int checksum = 0; checksum < 2; ++checksum) {
            size_t n = fixture_dual_data(p, &c, options, checksum);
            for (size_t cut = 0; cut < n; ++cut)
              CHECK(nanoamt_receive(g, 3, &c.discovery, p, cut, &packet) == NANOAMT_IGNORED);
            CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
            CHECK(packet.size == 5 && packet.protocol == 17 && packet.ip_size == n - 2);
            CHECK(packet.source.ip_version == (inner ? 6 : 4));
            CHECK(!memcmp(packet.data, "\x40\x00\x80\xff\x01", 5));
            if (checksum) {
              p[n - 1] ^= 1;
              CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
            }
          }
        size_t n = fixture_dual_data(p, &c, 0, 0);
        p[inner ? 25 : 17] ^= 1;
        if (!inner)
          ip_checksum(p + 2);
        CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == (asm_mode ? NANOAMT_PACKET : NANOAMT_IGNORED));
        CHECK(nanoamt_leave(g, 4) == NANOAMT_OK);
        CHECK(nanoamt_send(g, 4, &report) == NANOAMT_PACKET && report.size == 30 && report.bytes[0] == 7);
        CHECK(!memcmp(report.bytes + 2, "COOKIE", 6));
        CHECK(report.bytes[12] == 0x9c && report.bytes[13] == 0x40 && report.bytes[29] == 7);
        nanoamt_free(g);
        g = start(&c, &request, &report, 0);
        CHECK(nanoamt_leave(g, 4) == NANOAMT_OK);
        CHECK(nanoamt_send(g, 4, &report) == NANOAMT_PACKET && report.bytes[0] == 5);
        CHECK(report.bytes[offset + 8] == (asm_mode ? 3 : 6));
        nanoamt_free(g);
      }
}

static void teardown(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_config(&random);
  c.refresh_cap_ms = 1000;
  nanoamt_datagram request, report, old;
  uint8_t p[256];
  nanoamt_packet packet;
  nanoamt *g = start(&c, &request, &old, 1);
  int64_t now;
  do {
    now = nanoamt_next_timeout(g);
    CHECK(nanoamt_send(g, now, &request) == NANOAMT_PACKET);
  } while (request.bytes[0] != 3);
  CHECK(nanoamt_is_joined(g));
  size_t n = fixture_query(p, &request, 125, 3);
  CHECK(nanoamt_receive(g, now, &c.discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_send(g, now, &report) == NANOAMT_PACKET && report.bytes[0] == 5);
  old = report;
  now = nanoamt_next_timeout(g);
  CHECK(nanoamt_send(g, now, &request) == NANOAMT_PACKET && request.bytes[0] == 3);
  n = fixture_query(p, &request, 125, 1);
  p[n - 1] = 8;
  memcpy(p + 2, "NEWKEY", 6);
  CHECK(nanoamt_receive(g, now, &c.discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(!nanoamt_is_joined(g));
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_REPORTING);
  CHECK(nanoamt_send(g, now, &report) == NANOAMT_PACKET && report.bytes[0] == 7);
  CHECK(!nanoamt_is_joined(g));
  CHECK(nanoamt_get_state(g) == NANOAMT_STATE_REPORTING);
  CHECK(!memcmp(report.bytes + 2, old.bytes + 2, 10) && report.bytes[29] == 7);
  CHECK(nanoamt_send(g, now, &report) == NANOAMT_PACKET && report.bytes[0] == 5);
  CHECK(nanoamt_is_joined(g));
  CHECK(!memcmp(report.bytes + 2, "NEWKEY", 6));
  CHECK(nanoamt_leave(g, now) == NANOAMT_OK);
  CHECK(nanoamt_send(g, now, &report) == NANOAMT_PACKET && report.bytes[0] == 7 && report.bytes[29] == 8);
  CHECK(!memcmp(report.bytes + 2, "NEWKEY", 6));
  nanoamt_free(g);
  c.direct = 1;
  g = start(&c, &request, &report, 0);
  nanoamt_free(g);
}

static size_t fragment(uint8_t *out, const uint8_t *whole, int v6, size_t offset, size_t length, int more,
                       unsigned id) {
  memset(out, 0, 256);
  out[0] = 6;
  uint8_t *ip = out + 2;
  if (v6) {
    memcpy(ip, whole + 2, 40);
    ip[6] = 44;
    put16(ip + 4, (unsigned)length + 8);
    ip[40] = 17;
    put16(ip + 42, (unsigned)offset | (unsigned)more);
    put16(ip + 46, id);
    memcpy(ip + 48, whole + 42 + offset, length);
    return 50 + length;
  }
  memcpy(ip, whole + 2, 20);
  put16(ip + 2, (unsigned)length + 20);
  put16(ip + 4, id);
  put16(ip + 6, (unsigned)(offset / 8) | (more ? 0x2000u : 0));
  memcpy(ip + 20, whole + 22 + offset, length);
  ip_checksum(ip);
  return 22 + length;
}

static void reassembly(void) {
  for (int v6 = 0; v6 < 2; ++v6) {
    unsigned random = 0;
    nanoamt_config c = fixture_dual_config(&random, 0, v6, 0);
    nanoamt_datagram request, report;
    nanoamt_packet packet;
    nanoamt *g = start(&c, &request, &report, 0);
    uint8_t whole[256], p[256];
    fixture_dual_data(whole, &c, 0, 1);
    size_t n = fragment(p, whole, v6, 8, 5, 0, 42);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 8, 1, 42);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
    CHECK(packet.size == 5 && !memcmp(packet.data, "\x40\x00\x80\xff\x01", 5));
    n = fragment(p, whole, v6, 0, 8, 1, 90);
    for (size_t cut = 0; cut < n; ++cut)
      CHECK(nanoamt_receive(g, 3, &c.discovery, p, cut, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 8, 1, 43);
    CHECK(nanoamt_receive(g, 4, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    CHECK(nanoamt_receive(g, 4, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 8, 5, 0, 43);
    CHECK(nanoamt_receive(g, 4, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 8, 1, 44);
    CHECK(nanoamt_receive(g, 5, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 8, 5, 0, 44);
    CHECK(nanoamt_receive(g, 60005, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 7, 1, 45);
    CHECK(nanoamt_receive(g, 60006, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    if (v6) {
      n = fragment(p, whole, 1, 0, 13, 0, 44);
      CHECK(nanoamt_receive(g, 60006, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
      n = fragment(p, whole, 1, 0, 8, 1, 46);
      CHECK(nanoamt_receive(g, 60007, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
      n = fragment(p, whole, 1, 0, 13, 0, 46);
      CHECK(nanoamt_receive(g, 60007, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
      n = fragment(p, whole, 1, 8, 5, 0, 46);
      CHECK(nanoamt_receive(g, 60007, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
      for (unsigned part = 0; part < 2; ++part) {
        n = fragment(p, whole, 1, part ? 8 : 0, part ? 5 : 8, !part, 47);
        memmove(p + 50, p + 42, n - 42);
        memset(p + 42, 0, 8);
        p[8] = 0;
        p[42] = 44;
        n += 8;
        put16(p + 6, (unsigned)n - 42);
        CHECK(nanoamt_receive(g, 60008, &c.discovery, p, n, &packet) == (part ? NANOAMT_PACKET : NANOAMT_IGNORED));
      }
      CHECK(packet.ip_size == 61 && packet.ip_data[6] == 0 && packet.ip_data[40] == 17);
      CHECK(packet.size == 5 && !memcmp(packet.data, "\x40\x00\x80\xff\x01", 5));
    }
    nanoamt_free(g);
    g = start(&c, &request, &report, 0);
    for (unsigned id = 1; id <= 5; ++id) {
      n = fragment(p, whole, v6, 0, 8, 1, id);
      CHECK(nanoamt_receive(g, 2 + id, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    }
    n = fragment(p, whole, v6, 8, 5, 0, 5);
    CHECK(nanoamt_receive(g, 8, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
    n = fragment(p, whole, v6, 8, 5, 0, 1);
    CHECK(nanoamt_receive(g, 8, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
    nanoamt_free(g);
  }
}

static void mld_validation(void) {
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, 1, 1, 0);
  nanoamt *g = nanoamt_new(&c, 0);
  nanoamt_datagram request;
  nanoamt_packet packet;
  uint8_t p[256], query[256];
  CHECK(nanoamt_send(g, 0, &request) == NANOAMT_PACKET);
  size_t n = fixture_advertisement(p, &request, &c.discovery);
  CHECK(nanoamt_receive(g, 1, &c.discovery, p, n, &packet) == NANOAMT_OK);
  CHECK(nanoamt_send(g, 1, &request) == NANOAMT_PACKET);
  n = fixture_dual_query(query, &request, &c, 0x96, 1);
  for (size_t cut = 0; cut < n; ++cut)
    CHECK(nanoamt_receive(g, 2, &c.discovery, query, cut, &packet) == NANOAMT_IGNORED);
  const size_t changes[] = {0, 8, 12, 19, 36, 51, 54, 55, 60, 61, 68, 86};
  for (size_t i = 0; i < sizeof(changes) / sizeof(*changes); ++i) {
    memcpy(p, query, n);
    p[changes[i]] ^= changes[i] == 12 ? 0x10 : 1;
    CHECK(nanoamt_receive(g, 2, &c.discovery, p, n, &packet) == NANOAMT_IGNORED);
  }
  CHECK(nanoamt_receive(g, 2, &c.discovery, query, n, &packet) == NANOAMT_OK);
  nanoamt_free(g);
}

static void raw_ip(void) {
  for (int v6 = 0; v6 < 2; ++v6) {
    unsigned random = 0;
    nanoamt_config c = fixture_dual_config(&random, 0, v6, 0);
    c.port = 0;
    nanoamt_datagram request, report;
    nanoamt_packet packet;
    uint8_t p[256];
    nanoamt *g = start(&c, &request, &report, 0);
    size_t n = fixture_dual_data(p, &c, 0, 0);
    p[v6 ? 8 : 11] = v6 ? 58 : 1;
    if (!v6)
      ip_checksum(p + 2);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_PACKET);
    CHECK(packet.ip_data == p + 2 && packet.ip_size == n - 2 && packet.size == 13);
    nanoamt_free(g);
  }
}

static void mark_ecn(uint8_t *p, int v6, unsigned ecn) {
  if (v6)
    p[3] = (uint8_t)((p[3] & 0xcf) | (ecn << 4));
  else {
    p[3] = (uint8_t)((p[3] & 0xfc) | ecn);
    ip_checksum(p + 2);
  }
}

static void ecn(void) {
  /* RFC 6040 */
  static const int expected[4][4] = {{0, 0, 0, -1}, {1, 1, 1, 3}, {2, 1, 2, 3}, {3, 3, 3, 3}};
  for (int v6 = 0; v6 < 2; ++v6) {
    unsigned random = 0;
    nanoamt_config c = fixture_dual_config(&random, v6, v6, 0);
    c.ecn = 1;
    nanoamt_datagram request, report;
    nanoamt_packet packet;
    nanoamt *g = start(&c, &request, &report, 1);
    uint8_t p[256], whole[256];
    size_t n = fixture_dual_data(p, &c, 0, 1);
    CHECK(nanoamt_receive(g, 3, &c.discovery, p, n, &packet) == NANOAMT_ERROR_ARGUMENT);
    CHECK(!packet.data);
    CHECK(nanoamt_receive_ecn(g, 3, &c.discovery, p, n, 4, &packet) == NANOAMT_ERROR_ARGUMENT);
    for (unsigned inner = 0; inner < 4; ++inner)
      for (unsigned outer = 0; outer < 4; ++outer) {
        n = fixture_dual_data(p, &c, 0, 1);
        mark_ecn(p, v6, inner);
        int ret = nanoamt_receive_ecn(g, 3, &c.discovery, p, n, (int)outer, &packet);
        CHECK(ret == (expected[inner][outer] < 0 ? NANOAMT_IGNORED : NANOAMT_PACKET));
        if (ret == NANOAMT_PACKET) {
          CHECK(packet.tos == (0x2c | expected[inner][outer]));
          if (!v6)
            CHECK(sum16(packet.ip_data, 20) == 0);
        } else
          CHECK(packet.data == NULL);
      }
    if (!v6) {
      n = fixture_dual_data(p, &c, 0, 1);
      mark_ecn(p, 0, 2);
      p[12] ^= 1;
      CHECK(nanoamt_receive_ecn(g, 3, &c.discovery, p, n, 3, &packet) == NANOAMT_IGNORED);
    }
    fixture_dual_data(whole, &c, 0, 1);
    mark_ecn(whole, v6, 2);
    n = fragment(p, whole, v6, 8, 5, 0, 81);
    CHECK(nanoamt_receive_ecn(g, 4, &c.discovery, p, n, 3, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 8, 1, 81);
    CHECK(nanoamt_receive_ecn(g, 4, &c.discovery, p, n, 2, &packet) == NANOAMT_PACKET);
    CHECK((packet.tos & 3) == 3);
    n = fragment(p, whole, v6, 8, 5, 0, 82);
    CHECK(nanoamt_receive_ecn(g, 5, &c.discovery, p, n, 3, &packet) == NANOAMT_IGNORED);
    n = fragment(p, whole, v6, 0, 8, 1, 82);
    mark_ecn(p, v6, 0);
    CHECK(nanoamt_receive_ecn(g, 5, &c.discovery, p, n, 0, &packet) == NANOAMT_IGNORED);
    nanoamt_free(g);
  }
}

int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "dual"))
    dual_stack();
  else if (!strcmp(argv[1], "teardown"))
    teardown();
  else if (!strcmp(argv[1], "fragments"))
    reassembly();
  else if (!strcmp(argv[1], "mld"))
    mld_validation();
  else if (!strcmp(argv[1], "ecn"))
    ecn();
  else if (!strcmp(argv[1], "raw"))
    raw_ip();
  else
    return 2;
  printf("===AMT RFC %s OK===\n", argv[1]);
  return 0;
}
