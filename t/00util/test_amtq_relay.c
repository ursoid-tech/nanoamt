#include "fixtures.h"
#include "nanoamt/amtq_relay.h"
#include <limits.h>

typedef struct pair {
  nanoamtq *gateway;
  nanoamtq_relay *relay;
  nanoamt_config config;
  unsigned random;
  int resolve, context_opened;
  uint64_t connection_id;
} pair;
static uint64_t connection_ids;
static nanoamtq_membership interest(const nanoamt_config *c) {
  nanoamtq_membership m = {0};
  memcpy(m.source, c->source, 16);
  memcpy(m.group, c->group, 16);
  m.any_source = c->any_source;
  m.port = c->port;
  return m;
}
static void init(pair *p, int ipv6, int asm_mode) {
  memset(p, 0, sizeof(*p));
  p->resolve = 1;
  p->config = fixture_dual_config(&p->random, 0, ipv6, asm_mode);
  nanoamtq_config g = {0};
  g.ip_version = p->config.ip_version;
  g.random_bytes = fixture_random;
  g.random_context = &p->random;
  g.max_fragment_ranges = 1024;
  p->gateway = nanoamtq_new(&g, 0);
  nanoamtq_relay_config r = {0};
  r.connection_id = p->connection_id = ++connection_ids;
  p->relay = nanoamtq_relay_new(&r, 0);
  CHECK(p->gateway && p->relay);
  nanoamtq_membership m = interest(&p->config);
  CHECK(!nanoamtq_set_memberships(p->gateway, &m, 1));
}
static void cleanup(pair *p) {
  nanoamtq_free(p->gateway);
  nanoamtq_relay_free(p->relay);
}
static int gateway_step(pair *p, int64_t now) {
  nanoamtq_control out;
  int rc = nanoamtq_send(p->gateway, now, &out);
  CHECK(rc == NANOAMTQ_OK || rc == NANOAMTQ_PACKET);
  if (!rc)
    return 0;
  /* One-byte delivery also covers every control framing boundary. */
  for (size_t i = 0; i < out.size; ++i) {
    size_t consumed;
    rc = nanoamtq_relay_receive_control(p->relay, now, 0, out.bytes + i, 1, 0, &consumed);
    CHECK(consumed == 1);
    if (rc == NANOAMTQ_MEMBERSHIP) {
      CHECK(i + 1 == out.size && nanoamtq_relay_pending(p->relay));
      if (p->resolve) {
        uint64_t generation = nanoamtq_relay_generation(p->relay);
        CHECK(!nanoamtq_relay_authorize_all(p->relay, now, generation));
        if (!p->context_opened && nanoamt_memberships_count(nanoamtq_relay_authorized(p->relay))) {
          CHECK(!nanoamtq_relay_open_context(p->relay, now, 0));
          p->context_opened = 1;
        }
      }
    } else
      CHECK(rc == NANOAMTQ_OK);
  }
  return 1;
}
static int relay_step(pair *p, int64_t now) {
  nanoamtq_control out;
  int rc = nanoamtq_relay_send(p->relay, now, &out);
  CHECK(rc == NANOAMTQ_OK || rc == NANOAMTQ_PACKET);
  if (!rc)
    return 0;
  for (size_t i = 0; i < out.size; ++i)
    CHECK(!nanoamtq_receive_control(p->gateway, now, 0, out.bytes + i, 1, 0));
  return 1;
}
static void drive(pair *p, int64_t now) {
  for (unsigned i = 0; i < 32; ++i) {
    int progress = gateway_step(p, now);
    progress += relay_step(p, now);
    if (!progress)
      return;
  }
  CHECK(0);
}
static int send_control(nanoamtq_relay *r, int64_t now, uint64_t type, const uint8_t *p, size_t n) {
  uint8_t encoded[512];
  size_t size, consumed;
  nanoamtq_record record = {type, p, n};
  CHECK(!nanoamtq_record_encode(&record, encoded, sizeof(encoded), &size));
  int rc = nanoamtq_relay_receive_control(r, now, 0, encoded, size, 0, &consumed);
  CHECK(consumed == size);
  return rc;
}
static nanoamtq_relay *negotiated(uint64_t uni, unsigned contexts) {
  nanoamtq_relay_config config = {0};
  config.connection_id = ++connection_ids;
  config.peer_max_uni_streams = uni;
  config.max_contexts = contexts;
  nanoamtq_relay *r = nanoamtq_relay_new(&config, 0);
  CHECK(r);
  nanoamtq_control out;
  CHECK(nanoamtq_relay_send(r, 0, &out) == NANOAMTQ_PACKET);
  CHECK(out.size == 4 && !memcmp(out.bytes, "\0\2\0\1", 4));
  CHECK(!send_control(r, 0, NANOAMTQ_SETTINGS, (uint8_t[]){0, 1}, 2));
  return r;
}
static size_t packet(uint8_t *ip, const nanoamt_config *config, size_t payload) {
  uint8_t wrapped[128];
  size_t n = fixture_dual_data(wrapped, config, 0, 1) - 2;
  memcpy(ip, wrapped + 2, n);
  size_t header = config->ip_version == 6 ? 40 : 20;
  uint8_t *udp = ip + header;
  for (size_t i = 0; i < payload; ++i)
    udp[8 + i] = (uint8_t)(i ^ (i >> 8));
  n = header + 8 + payload;
  put16(udp + 4, (unsigned)(8 + payload));
  put16(udp + 6, 0);
  if (config->ip_version == 6) {
    put16(ip + 4, (unsigned)(8 + payload));
    uint32_t sum = 17u + (unsigned)(8 + payload);
    for (size_t i = 8; i < 40; i += 2)
      sum += ((unsigned)ip[i] << 8) | ip[i + 1];
    for (size_t i = 0; i < 8 + payload; ++i)
      sum += (unsigned)udp[i] << (i % 2 ? 0 : 8);
    while (sum >> 16)
      sum = (sum & 65535u) + (sum >> 16);
    unsigned checksum = (uint16_t)~sum;
    put16(udp + 6, checksum ? checksum : 65535);
  } else {
    put16(ip + 2, (unsigned)n);
    ip_checksum(ip);
  }
  return n;
}
static void exchange(void) {
  for (int ipv6 = 0; ipv6 < 2; ++ipv6)
    for (int asm_mode = 0; asm_mode < 2; ++asm_mode) {
      pair p;
      init(&p, ipv6, asm_mode);
      drive(&p, 0);
      CHECK(nanoamtq_is_ready(p.gateway) && nanoamtq_relay_is_ready(p.relay));
      CHECK(nanoamtq_relay_next_timeout(p.relay) == INT64_MAX);
      CHECK(nanoamtq_relay_generation(p.relay) == 1);
      uint8_t ip[512], bytes[512];
      size_t n = packet(ip, &p.config, 32);
      nanoamtq_relay_cursor cursor;
      nanoamtq_relay_datagram_output out;
      CHECK(!nanoamtq_relay_datagram_begin(p.relay, 1, 0, ip, n, &cursor));
      CHECK(nanoamtq_relay_datagram_next(p.relay, 1, &cursor, n + 4, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
      CHECK(out.format == NANOAMTQ_COMPLETE && out.size == n + 4 && out.connection_id == p.connection_id);
      CHECK(nanoamtq_relay_datagram_valid(p.relay, 1, &out, bytes, out.size));
      nanoamt_packet received;
      CHECK(nanoamtq_receive_datagram(p.gateway, 1, bytes, out.size, &received) == NANOAMTQ_PACKET);
      CHECK(received.size == 32 && !memcmp(received.data, ip + (ipv6 ? 48 : 28), 32));
      CHECK(received.source.port == 1234 && received.destination.port == p.config.port);
      CHECK(nanoamtq_relay_datagram_next(p.relay, 1, &cursor, 512, bytes, sizeof(bytes), &out) == NANOAMTQ_OK);
      if (ipv6)
        ip[23]++;
      else {
        ip[15]++;
        ip_checksum(ip);
      }
      CHECK(nanoamtq_relay_datagram_begin(p.relay, 1, 0, ip, n, &cursor) ==
            (asm_mode ? NANOAMTQ_OK : NANOAMTQ_IGNORED));
      /* Normal refresh keeps previous reception usable until new state. */
      drive(&p, 60000);
      CHECK(nanoamtq_relay_generation(p.relay) == 2 && nanoamtq_relay_is_ready(p.relay));
      cleanup(&p);
    }
}
static void fragments(void) {
  for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
    pair p;
    init(&p, ipv6, 0);
    drive(&p, 0);
    uint8_t ip[4096], frames[256][512];
    size_t n = packet(ip, &p.config, 3000), lengths[256];
    nanoamtq_relay_cursor cursor;
    nanoamtq_relay_datagram_output out;
    CHECK(!nanoamtq_relay_datagram_begin(p.relay, 1, 0, ip, n, &cursor));
    unsigned count = 0;
    size_t offset = 0;
    for (;;) {
      size_t budget = count % 3 == 0 ? 100 : count % 3 == 1 ? 63 : 257;
      int rc = nanoamtq_relay_datagram_next(p.relay, 1, &cursor, budget, frames[count], 512, &out);
      if (rc == NANOAMTQ_OK)
        break;
      CHECK(rc == NANOAMTQ_PACKET && out.format == NANOAMTQ_FRAGMENT && out.size <= budget);
      CHECK(nanoamtq_relay_datagram_valid(p.relay, 1, &out, frames[count], out.size));
      nanoamtq_datagram d;
      CHECK(!nanoamtq_datagram_decode(frames[count], out.size, &d));
      CHECK(d.packet_id == 1 && d.offset == offset && d.total_size == n + 2 && d.size);
      offset += d.size;
      lengths[count++] = out.size;
      CHECK(count < 256);
    }
    CHECK(offset == n + 2 && count > 2);
    nanoamt_packet received;
    for (unsigned i = count; i; --i) {
      int rc = nanoamtq_receive_datagram(p.gateway, 1, frames[i - 1], lengths[i - 1], &received);
      CHECK(rc == (i == 1 ? NANOAMTQ_PACKET : NANOAMTQ_IGNORED));
    }
    CHECK(received.size == 3000 && !memcmp(received.data, ip + (ipv6 ? 48 : 28), 3000));
    /* Abandoned sends still consume distinct IDs; check the 63/64 boundary. */
    for (uint64_t id = 2; id <= 65; ++id) {
      CHECK(!nanoamtq_relay_datagram_begin(p.relay, 1, 0, ip, n, &cursor));
      CHECK(nanoamtq_relay_datagram_next(p.relay, 1, &cursor, 60, frames[0], 512, &out) == NANOAMTQ_PACKET);
      nanoamtq_datagram d;
      CHECK(!nanoamtq_datagram_decode(frames[0], out.size, &d) && d.packet_id == id);
    }
    cleanup(&p);
  }
}
static void authorization(void) {
  pair p;
  init(&p, 0, 0);
  p.resolve = 0;
  drive(&p, 0);
  CHECK(nanoamtq_relay_pending(p.relay) && nanoamtq_relay_generation(p.relay) == 1);
  CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
  nanoamtq_authorization *first, *second;
  const nanoamt_memberships *requested = nanoamtq_relay_requested(p.relay);
  CHECK(!nanoamtq_relay_prepare_authorization(p.relay, 0, 1, requested, &first));
  CHECK(!nanoamtq_relay_prepare_authorization(p.relay, 0, 1, requested, &second));
  CHECK(!nanoamtq_relay_commit_authorization(p.relay, 0, first));
  CHECK(nanoamtq_relay_commit_authorization(p.relay, 0, first) == NANOAMTQ_ERROR_STALE);
  CHECK(nanoamtq_relay_commit_authorization(p.relay, 0, second) == NANOAMTQ_ERROR_STALE);
  nanoamtq_relay_authorization_free(first);
  nanoamtq_relay_authorization_free(second);
  CHECK(!nanoamtq_relay_open_context(p.relay, 0, 0));
  p.context_opened = 1;
  drive(&p, 0);
  uint8_t ip[256], bytes[256];
  size_t n = packet(ip, &p.config, 32);
  nanoamtq_relay_cursor cursor;
  nanoamtq_relay_datagram_output out;
  CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
  CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 40, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
  nanoamtq_membership m = interest(&p.config);
  m.source[3]++;
  CHECK(!nanoamtq_set_memberships(p.gateway, &m, 1));
  drive(&p, 1);
  CHECK(nanoamtq_relay_pending(p.relay) && nanoamtq_relay_generation(p.relay) == 2);
  /* Withdrawals revoke already-framed fragments before authorization. */
  CHECK(!nanoamtq_relay_datagram_valid(p.relay, 1, &out, bytes, out.size));
  CHECK(nanoamtq_relay_datagram_next(p.relay, 1, &cursor, 40, bytes, sizeof(bytes), &out) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_relay_datagram_begin(p.relay, 1, 0, ip, n, &cursor) == NANOAMTQ_IGNORED);
  CHECK(nanoamtq_relay_prepare_authorization(p.relay, 1, 1, requested, &first) == NANOAMTQ_ERROR_STALE);
  CHECK(!nanoamtq_relay_deny(p.relay, 1, 2));
  CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
  CHECK(nanoamt_memberships_count(nanoamtq_relay_requested(p.relay)) == 1);
  CHECK(!nanoamtq_relay_error(p.relay));
  pair foreign;
  init(&foreign, 0, 1);
  drive(&foreign, 0);
  CHECK(nanoamtq_relay_prepare_authorization(p.relay, 1, 2, nanoamtq_relay_authorized(foreign.relay), &first) ==
        NANOAMTQ_ERROR_POLICY);
  CHECK(!first && !nanoamtq_relay_error(p.relay));
  cleanup(&foreign);
  /* Later policy approval can grant the still-requested state. */
  CHECK(!nanoamtq_relay_authorize_all(p.relay, 2, 2));
  CHECK(nanoamt_memberships_subset(nanoamtq_relay_requested(p.relay), nanoamtq_relay_authorized(p.relay)));
  p.config.source[3]++;
  n = packet(ip, &p.config, 32);
  CHECK(!nanoamtq_relay_datagram_begin(p.relay, 2, 0, ip, n, &cursor));
  CHECK(nanoamtq_relay_datagram_next(p.relay, 2, &cursor, 256, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_relay_datagram_valid(p.relay, 2, &out, bytes, out.size));
  nanoamt_membership_config empty_config = {0};
  empty_config.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  nanoamt_memberships *empty = nanoamt_memberships_new(&empty_config, 2);
  CHECK(empty);
  CHECK(!nanoamtq_relay_prepare_authorization(p.relay, 2, 2, empty, &first));
  CHECK(!nanoamtq_relay_commit_authorization(p.relay, 2, first));
  CHECK(!nanoamtq_relay_datagram_valid(p.relay, 2, &out, bytes, out.size));
  nanoamtq_relay_authorization_free(first);
  nanoamt_memberships_free(empty);
  CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
  cleanup(&p);
}
static void native_fragments(void) {
  for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
    pair p;
    init(&p, ipv6, 0);
    drive(&p, 0);
    uint8_t original[128], fragment[128], bytes[256];
    packet(original, &p.config, 5);
    size_t header = ipv6 ? 40 : 20;
    nanoamt_packet received;
    for (unsigned pass = 0; pass < 2; ++pass) {
      size_t offset = pass ? 0 : 8, take = pass ? 8 : 5;
      memcpy(fragment, original, header);
      size_t n = header + take + (ipv6 ? 8 : 0);
      if (ipv6) {
        fragment[6] = 44;
        put16(fragment + 4, (unsigned)(8 + take));
        memcpy(fragment + 40, (uint8_t[]){17, 0, 0, 0, 0, 0, 0, 77}, 8);
        put16(fragment + 42, (unsigned)offset | pass);
      } else {
        put16(fragment + 2, (unsigned)n);
        put16(fragment + 4, 77);
        put16(fragment + 6, (unsigned)(offset / 8) | (pass ? 0x2000u : 0));
        ip_checksum(fragment);
      }
      memcpy(fragment + header + (ipv6 ? 8 : 0), original + header + offset, take);
      nanoamtq_relay_cursor cursor;
      nanoamtq_relay_datagram_output out;
      CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, fragment, n, &cursor));
      CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 256, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
      nanoamtq_datagram d;
      CHECK(!nanoamtq_datagram_decode(bytes, out.size, &d));
      CHECK(d.size == n + 2 && !memcmp(d.data + 2, fragment, n));
      CHECK(nanoamtq_relay_datagram_valid(p.relay, 0, &out, bytes, out.size));
      CHECK(nanoamtq_receive_datagram(p.gateway, 0, bytes, out.size, &received) ==
            (pass ? NANOAMTQ_PACKET : NANOAMTQ_IGNORED));
      if (pass)
        CHECK(received.size == 5 && !memcmp(received.data, original + header + 8, 5));
    }
    cleanup(&p);
  }
}
static void report_errors(void) {
  for (unsigned mutation = 0; mutation < 6; ++mutation) {
    pair p;
    init(&p, 0, 0);
    CHECK(gateway_step(&p, 0) && relay_step(&p, 0));
    CHECK(gateway_step(&p, 0) && relay_step(&p, 0));
    nanoamtq_control out;
    CHECK(nanoamtq_send(p.gateway, 0, &out) == NANOAMTQ_PACKET);
    nanoamtq_record record;
    size_t consumed;
    CHECK(!nanoamtq_record_decode(out.bytes, out.size, &record, &consumed));
    uint8_t body[256];
    CHECK(record.type == 1 && record.size < sizeof(body));
    size_t n = record.size;
    memcpy(body, record.data, n);
    switch (mutation) {
    case 0:
      body[1] = 1;
      break;
    case 1:
      body[2] = 1;
      break;
    case 2:
      body[8] ^= 1;
      break;
    case 3:
      body[n++] = 0; /* Trailing bytes outside the encapsulated IP are illegal. */
      break;
    case 4:
      body[44] = 7; /* A checksummed unknown membership record kind. */
      put16(body + 38, 0);
      put16(body + 38, sum16(body + 36, n - 36));
      break;
    case 5:
      body[0] = 3;
      body[1] = 1; /* A second Request cannot switch this connection to IPv6. */
      n = 8;
      break;
    }
    CHECK(send_control(p.relay, 0, 1, body, n) == NANOAMTQ_ERROR_PROTOCOL);
    CHECK(nanoamtq_relay_close_error(p.relay) == NANOAMTQ_CLOSE_AMT_MESSAGE);
    CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
    CHECK(nanoamtq_relay_send(p.relay, 0, &out) == NANOAMTQ_ERROR_PROTOCOL && !out.size);
    cleanup(&p);
  }
  pair p;
  init(&p, 0, 0);
  p.resolve = 0;
  drive(&p, 0);
  nanoamtq_authorization *token;
  CHECK(!nanoamtq_relay_prepare_authorization(p.relay, 0, 1, nanoamtq_relay_requested(p.relay), &token));
  size_t consumed;
  CHECK(nanoamtq_relay_receive_control(p.relay, 0, 0, NULL, 0, 1, &consumed) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_relay_close_error(p.relay) == NANOAMTQ_CLOSE_CONTROL_STREAM);
  CHECK(nanoamtq_relay_commit_authorization(p.relay, 0, token) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
  nanoamtq_relay_authorization_free(token);
  cleanup(&p);
}
static void control(void) {
  const uint8_t bad_settings[][8] = {{0, 0}, {0, 1, 0, 1}, {0, 1, 2, 4, 2, 5}, {0, 1, 1, 1}, {0, 3}};
  const size_t lengths[] = {2, 4, 6, 4, 2};
  for (unsigned i = 0; i < 5; ++i) {
    nanoamtq_relay_config config = {0};
    config.connection_id = 1;
    nanoamtq_relay *r = nanoamtq_relay_new(&config, 0);
    nanoamtq_control out;
    CHECK(nanoamtq_relay_send(r, 0, &out) == NANOAMTQ_PACKET);
    CHECK(send_control(r, 0, 0, bad_settings[i], lengths[i]) == NANOAMTQ_ERROR_PROTOCOL);
    CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_SETTINGS);
    nanoamtq_relay_free(r);
  }
  nanoamtq_relay_config config = {0};
  config.connection_id = 1;
  config.peer_max_uni_streams = 1;
  nanoamtq_relay *r = nanoamtq_relay_new(&config, 0);
  nanoamtq_control out;
  CHECK(nanoamtq_relay_send(r, 0, &out) == NANOAMTQ_PACKET);
  CHECK(!send_control(r, 0, 0, (uint8_t[]){0, 3, 1, 1, 9, 22}, 6));
  CHECK(!send_control(r, 0, 99, (uint8_t[]){1, 2, 3}, 3));
  CHECK(send_control(r, 0, 2, (uint8_t[]){0, 0}, 2) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_PROTOCOL);
  nanoamtq_relay_free(r);
  const uint8_t bad_requests[][8] = {{3, 2}, {3, 0, 1}, {3, 0, 0, 1}, {1, 0}, {7, 0}};
  for (unsigned i = 0; i < 5; ++i) {
    r = negotiated(0, 0);
    CHECK(send_control(r, 0, 1, bad_requests[i], 8) == NANOAMTQ_ERROR_PROTOCOL);
    CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_AMT_MESSAGE);
    nanoamtq_relay_free(r);
  }
  r = negotiated(0, 0);
  const uint8_t request[] = {3, 0, 0, 0, 1, 2, 3, 4};
  CHECK(!send_control(r, 0, 1, request, 8));
  CHECK(send_control(r, 0, 1, request, 8) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_AMT_MESSAGE);
  nanoamtq_relay_free(r);
  r = negotiated(0, 0);
  size_t consumed = 99;
  CHECK(nanoamtq_relay_receive_control(r, 0, 4, NULL, 0, 0, &consumed) == NANOAMTQ_ERROR_PROTOCOL && !consumed);
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_CONTROL_STREAM);
  nanoamtq_relay_free(r);
  r = negotiated(0, 0);
  CHECK(nanoamtq_relay_receive_datagram(r, 0, (uint8_t[]){0, 0, 6, 0}, 4) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_PROTOCOL);
  nanoamtq_relay_free(r);
  /* A coalesced record suffix remains intact while native joins are pending. */
  pair p;
  init(&p, 0, 0);
  CHECK(gateway_step(&p, 0) && relay_step(&p, 0));
  CHECK(gateway_step(&p, 0) && relay_step(&p, 0));
  nanoamtq_control report;
  CHECK(nanoamtq_send(p.gateway, 0, &report) == NANOAMTQ_PACKET);
  const uint8_t suffix[] = {17, 2, 7, 8};
  memcpy(report.bytes + report.size, suffix, sizeof(suffix));
  size_t combined = report.size + sizeof(suffix);
  CHECK(nanoamtq_relay_receive_control(p.relay, 0, 0, report.bytes, combined, 0, &consumed) == NANOAMTQ_MEMBERSHIP);
  CHECK(consumed == report.size);
  CHECK(nanoamtq_relay_receive_control(p.relay, 0, 0, suffix, sizeof(suffix), 0, &consumed) == NANOAMTQ_MEMBERSHIP);
  CHECK(!consumed);
  CHECK(!nanoamtq_relay_authorize_all(p.relay, 0, 1));
  CHECK(!nanoamtq_relay_receive_control(p.relay, 0, 0, suffix, sizeof(suffix), 0, &consumed));
  CHECK(consumed == sizeof(suffix));
  cleanup(&p);
}
static void contexts(void) {
  pair p;
  init(&p, 0, 0);
  drive(&p, 0);
  uint8_t ip[128], bytes[256];
  size_t n = packet(ip, &p.config, 16);
  nanoamtq_relay_cursor cursor;
  nanoamtq_relay_datagram_output out;
  CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
  CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 256, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
  CHECK(!nanoamtq_relay_close_context(p.relay, 0, 0));
  CHECK(!nanoamtq_relay_datagram_valid(p.relay, 0, &out, bytes, out.size));
  CHECK(!nanoamtq_relay_is_ready(p.relay));
  drive(&p, 0);
  CHECK(!nanoamtq_is_ready(p.gateway));
  CHECK(nanoamtq_relay_open_context(p.relay, 0, 0) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(!nanoamtq_relay_error(p.relay));
  const uint64_t ids[] = {63, 64, UINT64_C(0x3fffffffffffffff)};
  for (unsigned i = 0; i < 3; ++i) {
    CHECK(!nanoamtq_relay_open_context(p.relay, 0, ids[i]));
    CHECK(nanoamtq_relay_datagram_begin(p.relay, 0, ids[i], ip, n, &cursor) == NANOAMTQ_IGNORED);
    drive(&p, 0);
    CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, ids[i], ip, n, &cursor));
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 40, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
    CHECK(out.context_id == ids[i]);
    CHECK(nanoamtq_relay_datagram_valid(p.relay, 0, &out, bytes, out.size));
  }
  cleanup(&p);
  nanoamtq_relay *r = negotiated(0, 1);
  CHECK(nanoamtq_relay_open_context(r, 0, 1) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(!nanoamtq_relay_open_context(r, 0, 0));
  CHECK(nanoamtq_relay_open_context(r, 0, 1) == NANOAMTQ_ERROR_LIMIT);
  CHECK(send_control(r, 0, 4, (uint8_t[]){0}, 1) == NANOAMTQ_ERROR_PROTOCOL); /* ACK before emission */
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_CONTEXT);
  nanoamtq_relay_free(r);
  r = negotiated(0, 1);
  CHECK(!nanoamtq_relay_open_context(r, 0, 0));
  nanoamtq_control c;
  CHECK(nanoamtq_relay_send(r, 0, &c) == NANOAMTQ_PACKET);
  CHECK(!send_control(r, 0, 4, (uint8_t[]){0}, 1));
  CHECK(send_control(r, 0, 4, (uint8_t[]){0}, 1) == NANOAMTQ_ERROR_PROTOCOL);
  CHECK(nanoamtq_relay_close_error(r) == NANOAMTQ_CLOSE_CONTEXT);
  nanoamtq_relay_free(r);
}
static void bounds(void) {
  for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
    pair p;
    init(&p, ipv6, 0);
    drive(&p, 0);
    uint8_t ip[128], bytes[256];
    size_t n = packet(ip, &p.config, 5);
    nanoamtq_relay_cursor cursor;
    nanoamtq_relay_datagram_output out;
    CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 1, bytes, sizeof(bytes), &out) == NANOAMTQ_ERROR_BUFFER);
    CHECK(out.size > 1);
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 10, bytes, 1, &out) == NANOAMTQ_ERROR_BUFFER);
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 10, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
    nanoamtq_datagram d;
    CHECK(!nanoamtq_datagram_decode(bytes, out.size, &d) && d.packet_id == 1 && !d.offset);
    /* Smallest useful budget splits even the virtual two-byte AMT header. */
    nanoamt_packet received;
    CHECK(nanoamtq_receive_datagram(p.gateway, 0, bytes, out.size, &received) == NANOAMTQ_IGNORED);
    while (nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 6, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET) {
      int rc = nanoamtq_receive_datagram(p.gateway, 0, bytes, out.size, &received);
      CHECK(rc == NANOAMTQ_IGNORED || rc == NANOAMTQ_PACKET);
    }
    CHECK(received.size == 5);
    /* COMPLETE consumes no fragmented Packet ID. */
    CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, n + 4, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
    CHECK(out.format == NANOAMTQ_COMPLETE);
    CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
    CHECK(nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 10, bytes, sizeof(bytes), &out) == NANOAMTQ_PACKET);
    CHECK(out.packet_id == 2);
    cleanup(&p);
  }
  pair p;
  init(&p, 1, 0);
  drive(&p, 0);
  uint8_t *ip = malloc(65575), *bytes = malloc(65580);
  CHECK(ip && bytes);
  size_t n = packet(ip, &p.config, 65527);
  CHECK(n == 65575);
  nanoamtq_relay_cursor cursor;
  nanoamtq_relay_datagram_output out;
  CHECK(!nanoamtq_relay_datagram_begin(p.relay, 0, 0, ip, n, &cursor));
  nanoamt_packet received;
  int rc;
  while ((rc = nanoamtq_relay_datagram_next(p.relay, 0, &cursor, 1200, bytes, 65580, &out)) == NANOAMTQ_PACKET) {
    int rr = nanoamtq_receive_datagram(p.gateway, 0, bytes, out.size, &received);
    CHECK(rr == NANOAMTQ_IGNORED || rr == NANOAMTQ_PACKET);
  }
  CHECK(!rc && received.size == 65527 && !memcmp(received.data, ip + 48, 65527));
  free(ip);
  free(bytes);
  cleanup(&p);
}
static void full_state(void) {
  for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
    pair p;
    init(&p, ipv6, 0);
    nanoamtq_membership m[64];
    for (unsigned i = 0; i < 64; ++i) {
      m[i] = interest(&p.config);
      m[i].group[ipv6 ? 15 : 3] = (uint8_t)(i + 1);
    }
    CHECK(!nanoamtq_set_memberships(p.gateway, m, 64));
    drive(&p, 0);
    CHECK(nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)) == 64);
    for (unsigned i = 0; i < 64; ++i)
      m[i].group[ipv6 ? 14 : 2]++;
    CHECK(!nanoamtq_set_memberships(p.gateway, m, 64));
    drive(&p, 1);
    CHECK(nanoamtq_relay_generation(p.relay) == 2 && !nanoamtq_relay_error(p.relay));
    CHECK(nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)) == 64);
    CHECK(!nanoamtq_set_memberships(p.gateway, NULL, 0));
    drive(&p, 2);
    CHECK(!nanoamt_memberships_count(nanoamtq_relay_authorized(p.relay)));
    cleanup(&p);
  }
}
static void timeout(void) {
  nanoamtq_relay_config config = {0};
  config.connection_id = 1;
  nanoamtq_relay *r = nanoamtq_relay_new(&config, 0);
  CHECK(r && nanoamtq_relay_next_timeout(r) == 0);
  CHECK(nanoamtq_relay_tick(r, -1) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_relay_tick(r, INT64_MAX) == NANOAMTQ_ERROR_ARGUMENT);
  CHECK(nanoamtq_relay_tick(r, 10000) == NANOAMTQ_ERROR_TIMEOUT);
  CHECK(!nanoamtq_relay_close_error(r) && !nanoamtq_relay_is_ready(r));
  nanoamtq_relay_free(r);
  r = negotiated(0, 0);
  CHECK(!nanoamtq_relay_open_context(r, 0, 0));
  nanoamtq_control out;
  CHECK(nanoamtq_relay_send(r, 0, &out) == NANOAMTQ_PACKET);
  CHECK(nanoamtq_relay_next_timeout(r) == 10000);
  CHECK(nanoamtq_relay_tick(r, 10000) == NANOAMTQ_ERROR_TIMEOUT);
  nanoamtq_relay_free(r);
  r = negotiated(0, 0);
  size_t consumed;
  CHECK(!nanoamtq_relay_receive_control(r, 0, 0, (uint8_t[]){0x40}, 1, 0, &consumed));
  CHECK(consumed == 1 && nanoamtq_relay_next_timeout(r) == 10000);
  CHECK(nanoamtq_relay_tick(r, 10000) == NANOAMTQ_ERROR_TIMEOUT);
  nanoamtq_relay_free(r);
  pair p;
  init(&p, 0, 0);
  p.resolve = 0;
  drive(&p, 0);
  CHECK(nanoamtq_relay_pending(p.relay));
  CHECK(nanoamtq_relay_tick(p.relay, 10000) == NANOAMTQ_ERROR_TIMEOUT);
  cleanup(&p);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "exchange"))
    exchange();
  else if (!strcmp(argv[1], "fragments"))
    fragments();
  else if (!strcmp(argv[1], "native-fragments"))
    native_fragments();
  else if (!strcmp(argv[1], "authorization"))
    authorization();
  else if (!strcmp(argv[1], "control"))
    control();
  else if (!strcmp(argv[1], "report-errors"))
    report_errors();
  else if (!strcmp(argv[1], "contexts"))
    contexts();
  else if (!strcmp(argv[1], "bounds"))
    bounds();
  else if (!strcmp(argv[1], "full-state"))
    full_state();
  else if (!strcmp(argv[1], "timeout"))
    timeout();
  else
    CHECK(0);
  printf("===AMTQ relay %s OK===\n", argv[1]);
  return 0;
}
