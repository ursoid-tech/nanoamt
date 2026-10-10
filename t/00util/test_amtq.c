#include "fixtures.h"
#include "nanoamt/amtq.h"
#include <limits.h>

static nanoamtq_membership interest(const nanoamt_config *c) {
  nanoamtq_membership m = {0};
  memcpy(m.source, c->source, 16);
  memcpy(m.group, c->group, 16);
  m.any_source = c->any_source;
  m.port = c->port;
  return m;
}
static nanoamtq *create(nanoamt_config *c, unsigned incomplete, unsigned ranges) {
  nanoamtq_config config = {0};
  config.ip_version = c->ip_version;
  config.random_bytes = c->random_bytes;
  config.random_context = c->random_context;
  config.max_incomplete = incomplete;
  config.max_fragment_ranges = ranges;
  nanoamtq *g = nanoamtq_new(&config, 0);
  CHECK(g);
  nanoamtq_membership m = interest(c);
  CHECK(nanoamtq_set_memberships(g, &m, 1) == NANOAMTQ_OK);
  return g;
}
static nanoamtq_record decode(nanoamtq_control *out) {
  nanoamtq_record r;
  size_t consumed;
  CHECK(nanoamtq_record_decode(out->bytes, out->size, &r, &consumed) == NANOAMTQ_OK);
  CHECK(consumed == out->size);
  return r;
}
static int control(nanoamtq *g, int64_t now, uint64_t type, const uint8_t *p, size_t n) {
  uint8_t encoded[512];
  size_t size;
  nanoamtq_record r = {type, p, n};
  CHECK(nanoamtq_record_encode(&r, encoded, sizeof(encoded), &size) == NANOAMTQ_OK);
  return nanoamtq_receive_control(g, now, 0, encoded, size, 0);
}
static void negotiate(nanoamtq *g) {
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 0, &out) == NANOAMTQ_PACKET);
  CHECK(out.size == 4 && !memcmp(out.bytes, "\0\2\0\1", 4));
  const uint8_t settings[] = {0x40, 0, 0x40, 2, 0, 1};
  for (size_t i = 0; i < sizeof(settings); ++i)
    CHECK(nanoamtq_receive_control(g, 0, 0, settings + i, 1, 0) == NANOAMTQ_OK);
}
static void query(nanoamtq *g, nanoamt_config *c, int64_t now) {
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, now, &out) == NANOAMTQ_PACKET);
  nanoamtq_record r = decode(&out);
  CHECK(r.type == NANOAMTQ_AMT_CONTROL && r.size == 8 && r.data[0] == 3);
  CHECK(r.data[1] == (c->ip_version == 6) && r.data[2] == 0 && r.data[3] == 0);
  nanoamt_datagram request = {0};
  memcpy(request.bytes, r.data, r.size);
  uint8_t bytes[256];
  size_t n = fixture_dual_query(bytes, &request, c, 125, 0);
  memset(bytes + 2, 0, 6);
  CHECK(control(g, now, NANOAMTQ_AMT_CONTROL, bytes, n) == NANOAMTQ_OK);
}
static void ready(nanoamtq *g, nanoamt_config *c) {
  negotiate(g);
  query(g, c, 1);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
  nanoamtq_record r = decode(&out);
  CHECK(r.type == NANOAMTQ_AMT_CONTROL && r.data[0] == 5);
  CHECK(!memcmp(r.data + 1, "\0\0\0\0\0\0\0", 7));
  CHECK(control(g, 1, NANOAMTQ_CONTEXT, (uint8_t[]){0, 0}, 2) == NANOAMTQ_OK);
  CHECK(!nanoamtq_is_ready(g));
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
  CHECK(out.size == 3 && !memcmp(out.bytes, "\4\1\0", 3));
  CHECK(nanoamtq_is_ready(g));
}
static int data(nanoamtq *g, int64_t now, nanoamt_config *c, nanoamt_packet *packet) {
  uint8_t message[128], encoded[160];
  size_t n = fixture_dual_data(message, c, 1, 1), size;
  nanoamtq_datagram d = {0};
  d.data = message;
  d.size = n;
  CHECK(nanoamtq_datagram_encode(&d, encoded, sizeof(encoded), &size) == NANOAMTQ_OK);
  return nanoamtq_receive_datagram(g, now, encoded, size, packet);
}
static void wire(void) {
  uint8_t out[256];
  memset(out, 0xaa, sizeof(out));
  nanoamtq_record r = {NANOAMTQ_SETTINGS, (const uint8_t *)"\0\1", 2}, parsed;
  size_t size, consumed;
  CHECK(nanoamtq_record_encode(&r, out, 3, &size) == NANOAMTQ_ERROR_BUFFER);
  CHECK(size == 4 && out[0] == 0xaa);
  CHECK(nanoamtq_record_encode(&r, out, sizeof(out), &size) == NANOAMTQ_OK);
  CHECK(!memcmp(out, "\0\2\0\1", 4));
  for (size_t i = 0; i < size; ++i)
    CHECK(nanoamtq_record_decode(out, i, &parsed, &consumed) == NANOAMTQ_INCOMPLETE && consumed == 0);
  CHECK(nanoamtq_record_decode(out, size, &parsed, &consumed) == 0 && consumed == size);
  const uint8_t excessive[] = {0, 0x80, 1, 0, 0x34};
  CHECK(nanoamtq_record_decode(excessive, sizeof(excessive), &parsed, &consumed) == NANOAMTQ_ERROR_PROTOCOL);
  const uint64_t ids[] = {63, 64, 16383, 16384, 1073741823, 1073741824, UINT64_C(0x3fffffffffffffff)};
  const size_t lengths[] = {1, 2, 2, 4, 4, 8, 8};
  for (size_t i = 0; i < sizeof(ids) / sizeof(*ids); ++i) {
    r.type = ids[i];
    CHECK(nanoamtq_record_encode(&r, out, sizeof(out), &size) == 0 && size == lengths[i] + 3);
    CHECK(nanoamtq_record_decode(out, size, &parsed, &consumed) == 0 && parsed.type == ids[i]);
  }
  r.type = UINT64_C(0x4000000000000000);
  CHECK(nanoamtq_record_encode(&r, out, sizeof(out), &size) == NANOAMTQ_ERROR_ARGUMENT);
  nanoamtq_datagram d = {NANOAMTQ_FRAGMENT, 9, 64, 100, 3, (const uint8_t *)"abc", 3}, view;
  CHECK(nanoamtq_datagram_encode(&d, out, sizeof(out), &size) == 0);
  const uint8_t expected[] = {1, 9, 0x40, 0x40, 0x40, 0x64, 3, 'a', 'b', 'c'};
  CHECK(size == sizeof(expected) && !memcmp(out, expected, size));
  CHECK(nanoamtq_datagram_decode(out, size, &view) == 0 && view.packet_id == 64 && view.offset == 3);
  for (size_t i = 0; i < 8; ++i)
    CHECK(nanoamtq_datagram_decode(out, i, &view) == NANOAMTQ_ERROR_PROTOCOL);
  d.offset = 99;
  CHECK(nanoamtq_datagram_encode(&d, out, sizeof(out), &size) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_datagram_decode((uint8_t[]){0, 0}, 2, &view) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_datagram_decode((uint8_t[]){22, 0}, 2, &view) == NANOAMTQ_OK && view.format == 22);
}
static void lifecycle(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng);
  nanoamtq *g = create(&c, 0, 0);
  CHECK(nanoamtq_next_timeout(g) == 0);
  ready(g, &c);
  CHECK(nanoamtq_next_timeout(g) == 60001);
  nanoamt_packet packet;
  CHECK(data(g, 2, &c, &packet) == NANOAMTQ_PACKET);
  CHECK(packet.size == 5 && packet.ip_size == 37 && packet.destination.port == 5000);
  packet.data[0] = 17;
  CHECK(packet.ip_data[packet.ip_size - 5] == 17);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 60001, &out) == NANOAMTQ_PACKET);
  CHECK(data(g, 60002, &c, &packet) == NANOAMTQ_PACKET);
  nanoamt_datagram request = {0};
  nanoamtq_record r = decode(&out);
  memcpy(request.bytes, r.data, r.size);
  uint8_t q[128];
  size_t n = fixture_query(q, &request, 1, 0);
  memset(q + 2, 0, 6);
  CHECK(control(g, 60002, 1, q, n) == 0);
  CHECK(nanoamtq_send(g, 60002, &out) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_next_timeout(g) == 61002);
  CHECK(nanoamtq_set_memberships(g, NULL, 0) == 0);
  CHECK(data(g, 60003, &c, &packet) == NANOAMTQ_IGNORED && !packet.data);
  CHECK(nanoamtq_send(g, 60003, &out) == NANOAMTQ_PACKET);
  r = decode(&out);
  CHECK(r.data[44] == 1 && r.data[46] == 0 && r.data[47] == 0);
  CHECK(control(g, 60004, NANOAMTQ_CONTEXT_CLOSE, (uint8_t[]){0}, 1) == 0);
  CHECK(!nanoamtq_is_ready(g));
  CHECK(control(g, 60004, NANOAMTQ_CONTEXT, (uint8_t[]){1, 0}, 2) == 0);
  CHECK(nanoamtq_send(g, 60004, &out) == NANOAMTQ_PACKET);
  CHECK(control(g, 60004, NANOAMTQ_CONTEXT, (uint8_t[]){0, 0}, 2) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_CONTEXT);
  CHECK(!nanoamtq_is_ready(g) && nanoamtq_next_timeout(g) == INT64_MAX);
  CHECK(data(g, 60005, &c, &packet) == NANOAMTQ_ERROR_PROTOCOL);
  nanoamtq_free(g);
}
static void membership(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng), other = c;
  nanoamtq *g = create(&c, 0, 0);
  ready(g, &c);
  nanoamtq_membership m[4];
  m[0] = interest(&c);
  m[1] = m[0];
  m[1].source[3]++;
  m[2] = m[0];
  m[2].port++;
  m[3] = m[0];
  m[3].group[3]++;
  m[3].any_source = 1;
  CHECK(nanoamtq_set_memberships(g, m, 4) == 0);
  nanoamt_packet packet;
  other.source[3]++;
  CHECK(data(g, 2, &other, &packet) == NANOAMTQ_IGNORED);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 2, &out) == NANOAMTQ_PACKET);
  nanoamtq_record r = decode(&out);
  CHECK(r.size == 68 && sum16(r.data + 12, 24) == 0 && sum16(r.data + 36, r.size - 36) == 0);
  CHECK(r.data[43] == 2 && r.data[44] == 1 && r.data[47] == 2);
  CHECK(!memcmp(r.data + 52, m[0].source, 4) && !memcmp(r.data + 56, m[1].source, 4));
  CHECK(r.data[60] == 2 && r.data[63] == 0);
  CHECK(data(g, 3, &other, &packet) == NANOAMTQ_PACKET);
  other.port++;
  CHECK(data(g, 3, &other, &packet) == NANOAMTQ_IGNORED);
  other = c;
  other.port++;
  CHECK(data(g, 3, &other, &packet) == NANOAMTQ_PACKET);
  other = c;
  other.group[3]++;
  other.source[3] += 20;
  CHECK(data(g, 3, &other, &packet) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_set_memberships(g, m, 1) == 0);
  CHECK(data(g, 4, &other, &packet) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_send(g, 4, &out) == NANOAMTQ_PACKET);
  r = decode(&out);
  CHECK(r.data[43] == 2 && r.data[56] == 1 && r.data[59] == 0);
  nanoamtq_membership invalid = m[0];
  memset(invalid.group, 0, 16);
  CHECK(nanoamtq_set_memberships(g, &invalid, 1) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(data(g, 5, &c, &packet) == NANOAMTQ_PACKET);
  nanoamtq_free(g);
}
static void ipv6(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_dual_config(&rng, 0, 1, 0);
  nanoamtq *g = create(&c, 0, 0);
  ready(g, &c);
  nanoamt_packet packet;
  CHECK(data(g, 2, &c, &packet) == NANOAMTQ_PACKET);
  CHECK(packet.source.ip_version == 6 && packet.size == 5);
  nanoamtq_membership m[2] = {interest(&c), interest(&c)};
  m[1].source[15]++;
  CHECK(nanoamtq_set_memberships(g, m, 2) == 0);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 3, &out) == NANOAMTQ_PACKET);
  nanoamtq_record r = decode(&out);
  CHECK(r.size == 120 && r.data[60] == 143 && r.data[67] == 1 && r.data[71] == 2);
  uint8_t copy[256];
  memcpy(copy, r.data, r.size);
  fixture_checksum6(copy + 12, copy + 60, r.size - 60, 58, 2);
  CHECK(!memcmp(copy, r.data, r.size));
  c.source[15]++;
  CHECK(data(g, 4, &c, &packet) == NANOAMTQ_PACKET);
  nanoamtq_free(g);
}
static int raw_data(nanoamtq *g, int64_t now, uint64_t context_id, const uint8_t *p, size_t n, nanoamt_packet *packet) {
  uint8_t encoded[256];
  size_t size;
  nanoamtq_datagram d = {0};
  d.context_id = context_id;
  d.data = p;
  d.size = n;
  CHECK(nanoamtq_datagram_encode(&d, encoded, sizeof(encoded), &size) == 0);
  return nanoamtq_receive_datagram(g, now, encoded, size, packet);
}
static void packets(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng);
  nanoamtq *g = create(&c, 0, 0);
  nanoamt_packet packet;
  CHECK(data(g, 0, &c, &packet) == NANOAMTQ_IGNORED);
  ready(g, &c);
  uint8_t good[128], bad[128];
  size_t n = fixture_data(good, &c, 0, 1);
  CHECK(raw_data(g, 2, 9, good, n, &packet) == NANOAMTQ_IGNORED);
  for (size_t cut = 1; cut < n; ++cut)
    CHECK(raw_data(g, 2, 0, good, cut, &packet) == NANOAMTQ_IGNORED && !packet.data);
  const size_t changes[] = {0, 1, 2, 4, 12, 14, 18, 28, 34};
  for (size_t i = 0; i < sizeof(changes) / sizeof(*changes); ++i) {
    memcpy(bad, good, n);
    bad[changes[i]] ^= 1;
    CHECK(raw_data(g, 2, 0, bad, n, &packet) == NANOAMTQ_IGNORED && !packet.data);
  }
  memcpy(bad, good, n);
  bad[n] = 0;
  CHECK(raw_data(g, 2, 0, bad, n + 1, &packet) == NANOAMTQ_IGNORED);
  uint8_t first[128], last[128];
  memcpy(first, good, 30);
  put16(first + 4, 28);
  put16(first + 8, 0x2000);
  ip_checksum(first + 2);
  memcpy(last, good, 22);
  memcpy(last + 22, good + 30, 5);
  put16(last + 4, 25);
  put16(last + 8, 1);
  ip_checksum(last + 2);
  CHECK(raw_data(g, 3, 0, last, 27, &packet) == NANOAMTQ_IGNORED);
  CHECK(raw_data(g, 3, 0, first, 30, &packet) == NANOAMTQ_PACKET);
  CHECK(packet.size == 5 && !memcmp(packet.data, good + 30, 5));
  CHECK(raw_data(g, 4, 0, last, 27, &packet) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_set_memberships(g, NULL, 0) == 0);
  CHECK(raw_data(g, 4, 0, first, 30, &packet) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_error(g) == 0);
  CHECK(nanoamtq_receive_datagram(g, 4, (uint8_t[]){0, 0}, 2, &packet) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_PROTOCOL);
  nanoamtq_free(g);
}
static void control_errors(void) {
  const uint8_t bad[][8] = {{0, 0}, {0, 1, 0, 1}, {0, 1, 9, 0, 9, 1}, {0, 1, 1, 0}, {0}, {9, 1}};
  const size_t sizes[] = {2, 4, 6, 4, 1, 2};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
    unsigned rng = 0;
    nanoamt_config c = fixture_config(&rng);
    nanoamtq *g = create(&c, 0, 0);
    CHECK(control(g, 0, NANOAMTQ_SETTINGS, bad[i], sizes[i]) == NANOAMTQ_ERROR_PROTOCOL);
    CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_SETTINGS);
    nanoamtq_free(g);
  }
  for (unsigned variant = 0; variant < 10; ++variant) {
    unsigned rng = 0;
    nanoamt_config c = fixture_config(&rng);
    nanoamtq *g = create(&c, 0, 0);
    nanoamtq_control out;
    if (variant == 0) {
      CHECK(control(g, 0, 99, NULL, 0) == NANOAMTQ_ERROR_PROTOCOL);
      CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_PROTOCOL);
    } else if (variant == 1 || variant == 2) {
      CHECK(nanoamtq_receive_control(g, 0, variant == 1 ? 3 : 0, NULL, 0, variant == 2) == NANOAMTQ_ERROR_PROTOCOL);
      CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_CONTROL_STREAM);
    } else {
      negotiate(g);
      if (variant == 3) {
        CHECK(control(g, 0, 0, (uint8_t[]){0, 1}, 2) == NANOAMTQ_ERROR_PROTOCOL);
        CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_SETTINGS);
      } else if (variant == 4) {
        CHECK(control(g, 0, 2, (uint8_t[]){1, 0}, 2) == NANOAMTQ_ERROR_PROTOCOL);
        CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_CONTEXT);
      } else if (variant == 5) {
        CHECK(control(g, 0, 2, (uint8_t[]){0, 1}, 2) == NANOAMTQ_ERROR_PROTOCOL);
        CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_CONTEXT);
      } else {
        CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
        nanoamtq_record r = decode(&out);
        nanoamt_datagram request = {0};
        memcpy(request.bytes, r.data, r.size);
        uint8_t q[128];
        size_t n = fixture_query(q, &request, 125, 0);
        memset(q + 2, 0, 6);
        if (variant == 6)
          q[2] = 1;
        if (variant == 7)
          q[8] ^= 1;
        if (variant == 8)
          q[1] = 1;
        if (variant == 9)
          q[n++] = 0;
        CHECK(control(g, 1, 1, q, n) == NANOAMTQ_ERROR_PROTOCOL);
        CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_AMT_MESSAGE);
      }
    }
    nanoamtq_free(g);
  }
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng);
  nanoamtq *g = create(&c, 0, 0);
  negotiate(g);
  const uint8_t coalesced[] = {63, 1, 55, 2, 2, 0, 0, 63, 0};
  CHECK(nanoamtq_receive_control(g, 0, 0, coalesced, sizeof(coalesced), 0) == 0);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 0, &out) == NANOAMTQ_PACKET && out.bytes[0] == 4);
  const uint8_t excessive[] = {63, 0x80, 1, 0, 0x34};
  CHECK(nanoamtq_receive_control(g, 0, 0, excessive, sizeof(excessive), 0) == NANOAMTQ_ERROR_PROTOCOL);
  nanoamtq_free(g);
}
static int fragment(nanoamtq *g, int64_t now, uint64_t id, const uint8_t *message, size_t total, size_t offset,
                    size_t n, nanoamt_packet *packet) {
  nanoamtq_datagram d = {NANOAMTQ_FRAGMENT, 0, id, total, offset, message + offset, n};
  uint8_t bytes[256];
  size_t size;
  CHECK(nanoamtq_datagram_encode(&d, bytes, sizeof(bytes), &size) == 0);
  return nanoamtq_receive_datagram(g, now, bytes, size, packet);
}
static void fragments(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng);
  nanoamtq *g = create(&c, 1, 3);
  ready(g, &c);
  uint8_t message[128], corrupt[128];
  size_t total = fixture_data(message, &c, 1, 1);
  nanoamt_packet packet;
  CHECK(fragment(g, 2, 0, message, total, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 3, 0, message, total, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 4, 0, message, total, 0, 24, &packet) == NANOAMTQ_PACKET);
  CHECK(packet.size == 5);
  CHECK(fragment(g, 5, 1, message, total, 0, 24, &packet) == NANOAMTQ_IGNORED);
  memcpy(corrupt, message, total);
  corrupt[20] ^= 1;
  CHECK(fragment(g, 6, 1, corrupt, total, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 7, 1, message, total, 24, total - 24, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 8, 2, message, total, 0, 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 9, 1, message, total, 0, 24, &packet) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_next_timeout(g) == 5009);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, 5009, &out) == 0);
  CHECK(nanoamtq_next_timeout(g) == 60001);
  CHECK(fragment(g, 5010, 1, message, total, 24, total - 24, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5011, 3, message, total, 0, 1, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5012, 3, message, total, 1, 1, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5013, 3, message, total, 2, 1, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5014, 3, message, total, 3, total - 3, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5015, 4, message, total, 0, 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5016, 4, message, total + 1, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5017, 4, message, total, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(fragment(g, 5018, 5, message, total, 0, 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(control(g, 5018, 3, (uint8_t[]){0}, 1) == 0);
  CHECK(nanoamtq_next_timeout(g) == 60001);
  CHECK(fragment(g, 5019, 5, message, total, 20, total - 20, &packet) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_error(g) == 0);
  nanoamtq_free(g);
}
static int broken_random(void *ctx, void *bytes, size_t size) {
  (void)ctx;
  (void)bytes;
  (void)size;
  return -1;
}
static void limits(void) {
  unsigned rng = 0;
  nanoamt_config c = fixture_config(&rng);
  nanoamtq *g = create(&c, 0, 0);
  nanoamtq_control out;
  CHECK(nanoamtq_send(g, -1, &out) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_send(g, INT64_MAX, &out) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_send(g, 0, &out) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_send(g, 10000, &out) == NANOAMTQ_ERROR_TIMEOUT);
  CHECK(nanoamtq_close_error(g) == 0 && !nanoamtq_is_ready(g));
  nanoamtq_free(g);
  g = create(&c, 0, 0);
  negotiate(g);
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_send(g, 10001, &out) == NANOAMTQ_ERROR_TIMEOUT);
  nanoamtq_free(g);
  c.random_bytes = broken_random;
  g = create(&c, 0, 0);
  negotiate(g);
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_ERROR_RANDOM);
  CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_INTERNAL);
  nanoamtq_free(g);
  c.random_bytes = fixture_random;
  g = create(&c, 0, 0);
  negotiate(g);
  for (unsigned i = 0; i < 64; ++i)
    CHECK(control(g, 0, 2, (uint8_t[]){(uint8_t)i, 0}, 2) == 0);
  CHECK(control(g, 0, 2, (uint8_t[]){0x40, 0x40, 0}, 3) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_close_error(g) == NANOAMTQ_CLOSE_EXCESSIVE_LOAD);
  nanoamtq_free(g);
  g = create(&c, 0, 0);
  ready(g, &c);
  nanoamtq_membership m[64];
  for (unsigned i = 0; i < 64; ++i) {
    m[i] = interest(&c);
    m[i].group[3] = (uint8_t)i;
  }
  CHECK(nanoamtq_set_memberships(g, m, 65) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_set_memberships(g, m, 64) == 0);
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
  for (unsigned i = 0; i < 64; ++i)
    m[i].group[2]++;
  CHECK(nanoamtq_set_memberships(g, m, 64) == 0);
  CHECK(nanoamtq_send(g, 1, &out) == NANOAMTQ_PACKET);
  nanoamtq_record r = decode(&out);
  CHECK(r.data[42] == 0 && r.data[43] == 128 && out.size < sizeof(out.bytes));
  nanoamtq_free(g);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "wire"))
    wire();
  else if (!strcmp(argv[1], "lifecycle"))
    lifecycle();
  else if (!strcmp(argv[1], "membership"))
    membership();
  else if (!strcmp(argv[1], "ipv6"))
    ipv6();
  else if (!strcmp(argv[1], "packets"))
    packets();
  else if (!strcmp(argv[1], "control"))
    control_errors();
  else if (!strcmp(argv[1], "fragments"))
    fragments();
  else if (!strcmp(argv[1], "limits"))
    limits();
  else
    CHECK(0);
  printf("===AMTQ %s OK===\n", argv[1]);
  return 0;
}
