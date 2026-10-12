#include "fixtures.h"
#include "nanoamt/relay.h"
#include <limits.h>

/* Deterministic TEST ONLY keyed hash. Production adapters use real HMAC. */
static int test_mac(void *ctx, const uint8_t key[32], const uint8_t *bytes, size_t size, uint8_t out[6]) {
  (void)ctx;
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < 32; ++i)
    hash = (hash ^ key[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < size; ++i)
    hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < 6; ++i) {
    out[i] = (uint8_t)hash;
    hash >>= 8;
  }
  return 0;
}
static nanoamt_endpoint peer_for(const nanoamt_config *config, unsigned port) {
  nanoamt_endpoint p = config->discovery;
  p.ip[config->discovery.ip_version == 6 ? 15 : 3] = 77;
  p.port = (uint16_t)port;
  return p;
}
static nanoamt_relay *new_relay(unsigned *random, unsigned limit) {
  nanoamt_relay_config c = {0};
  c.random_bytes = fixture_random;
  c.random_context = random;
  c.response_mac = test_mac;
  c.max_clients = limit;
  nanoamt_relay *r = nanoamt_relay_new(&c, 0);
  CHECK(r);
  return r;
}
static nanoamt *join(nanoamt_relay *r, nanoamt_config *config, const nanoamt_endpoint *peer, int64_t now,
                     nanoamt_datagram *report) {
  nanoamt *g = nanoamt_new(config, now);
  CHECK(g);
  nanoamt_datagram request;
  nanoamt_relay_control reply;
  nanoamt_packet packet;
  CHECK(nanoamt_send(g, now, &request) == NANOAMT_PACKET);
  CHECK(nanoamt_relay_receive(r, now, peer, &config->discovery, request.bytes, request.size, &reply) == NANOAMT_PACKET);
  CHECK(reply.source.port == config->discovery.port && reply.destination.port == peer->port);
  CHECK(nanoamt_receive(g, now, &reply.source, reply.bytes, reply.size, &packet) == NANOAMT_OK);
  if (!config->direct) {
    CHECK(nanoamt_send(g, now, &request) == NANOAMT_PACKET);
    CHECK(nanoamt_relay_receive(r, now, peer, &config->discovery, request.bytes, request.size, &reply) ==
          NANOAMT_PACKET);
    CHECK(nanoamt_receive(g, now, &reply.source, reply.bytes, reply.size, &packet) == NANOAMT_OK);
  }
  CHECK(nanoamt_send(g, now, report) == NANOAMT_PACKET);
  CHECK(nanoamt_relay_receive(r, now, peer, &config->discovery, report->bytes, report->size, &reply) == NANOAMT_OK);
  CHECK(nanoamt_is_joined(g));
  return g;
}
static size_t data(uint8_t *bytes, const nanoamt_config *config, size_t payload) {
  uint8_t wrapped[128];
  size_t n = fixture_dual_data(wrapped, config, 0, 1) - 2;
  memcpy(bytes, wrapped + 2, n);
  if (payload > 5) {
    size_t header = config->ip_version == 6 ? 40 : 20;
    uint8_t *udp = bytes + header;
    for (size_t i = 5; i < payload; ++i)
      udp[8 + i] = (uint8_t)i;
    n = header + 8 + payload;
    put16(udp + 4, (unsigned)(8 + payload));
    put16(udp + 6, 0);
    if (config->ip_version == 6) {
      put16(bytes + 4, (unsigned)(8 + payload));
      /* Larger buffers exceed the small fixture's pseudo-header scratch. */
      uint32_t sum = 17u + (unsigned)(8 + payload);
      for (size_t i = 8; i < 40; i += 2)
        sum += ((unsigned)bytes[i] << 8) | bytes[i + 1];
      for (size_t i = 0; i < 8 + payload; ++i)
        sum += (unsigned)udp[i] << (i % 2 ? 0 : 8);
      while (sum >> 16)
        sum = (sum & 65535u) + (sum >> 16);
      put16(udp + 6, (uint16_t)~sum ? (uint16_t)~sum : 65535);
    } else {
      put16(bytes + 2, (unsigned)n);
      ip_checksum(bytes);
    }
  }
  return n;
}
static void exchange(void) {
  for (int outer6 = 0; outer6 < 2; ++outer6)
    for (int inner6 = 0; inner6 < 2; ++inner6)
      for (int asm_mode = 0; asm_mode < 2; ++asm_mode) {
        unsigned random = 0;
        nanoamt_relay *r = new_relay(&random, 0);
        nanoamt_config config = fixture_dual_config(&random, outer6, inner6, asm_mode);
        config.ecn = 1;
        nanoamt_endpoint peer = peer_for(&config, 40000);
        nanoamt_datagram report;
        nanoamt *g = join(r, &config, &peer, 0, &report);
        nanoamt_memberships *snapshot = NULL;
        CHECK(!nanoamt_relay_snapshot(r, 0, &snapshot));
        CHECK(nanoamt_memberships_count(snapshot) == 1);
        nanoamt_memberships_free(snapshot);
        uint8_t ip[256], bytes[512];
        size_t n = data(ip, &config, 5);
        if (inner6)
          ip[1] = (uint8_t)((ip[1] & 0xcfu) | 0x20u);
        else {
          ip[1] |= 2;
          ip_checksum(ip);
        }
        nanoamt_relay_forward cursor;
        nanoamt_relay_output out;
        CHECK(!nanoamt_relay_forward_begin(r, 0, ip, n, &cursor));
        CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
        CHECK(out.size == n + 2 && out.destination.port == peer.port && out.tos == 2);
        CHECK(nanoamt_relay_output_valid(r, 0, &out, bytes, out.size));
        nanoamt_packet packet;
        CHECK(nanoamt_receive_ecn(g, 0, &out.source, bytes, out.size, 3, &packet) == NANOAMT_PACKET);
        CHECK(packet.size == 5 && (packet.tos & 3) == 3 && packet.source.port == 1234);
        CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_OK);
        CHECK(!nanoamt_leave(g, 1));
        CHECK(nanoamt_send(g, 1, &report) == NANOAMT_PACKET && report.bytes[0] == 7);
        nanoamt_relay_control reply;
        CHECK(!nanoamt_relay_receive(r, 1, &peer, &config.discovery, report.bytes, report.size, &reply));
        CHECK(!nanoamt_relay_snapshot(r, 1, &snapshot));
        CHECK(!nanoamt_memberships_count(snapshot));
        nanoamt_memberships_free(snapshot);
        nanoamt_free(g);
        nanoamt_relay_free(r);
      }
}
static void fanout(void) {
  unsigned random = 0;
  nanoamt_relay *r = new_relay(&random, 0);
  nanoamt_config config = fixture_config(&random);
  nanoamt_endpoint a = peer_for(&config, 40000), b = peer_for(&config, 40001);
  nanoamt_datagram report;
  nanoamt *ga = join(r, &config, &a, 0, &report), *gb = join(r, &config, &b, 0, &report);
  uint8_t ip[128], bytes[256], queued[256];
  size_t n = data(ip, &config, 5);
  nanoamt_relay_forward cursor;
  nanoamt_relay_output out, pending;
  CHECK(!nanoamt_relay_forward_begin(r, 0, ip, n, &cursor));
  CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, 1, &out) == NANOAMT_RELAY_ERROR_BUFFER);
  CHECK(out.size == n + 2);
  CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
  pending = out;
  memcpy(queued, bytes, out.size);
  nanoamt *leaver = out.destination.port == a.port ? ga : gb;
  nanoamt_endpoint leaving_peer = out.destination.port == a.port ? a : b;
  CHECK(!nanoamt_leave(leaver, 1));
  CHECK(nanoamt_send(leaver, 1, &report) == NANOAMT_PACKET);
  nanoamt_relay_control control;
  CHECK(!nanoamt_relay_receive(r, 1, &leaving_peer, &config.discovery, report.bytes, report.size, &control));
  CHECK(!nanoamt_relay_output_valid(r, 1, &pending, queued, pending.size));
  CHECK(nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
  CHECK(out.destination.port != leaving_peer.port);
  CHECK(nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_OK);
  nanoamt_memberships *snapshot;
  CHECK(!nanoamt_relay_snapshot(r, 1, &snapshot));
  CHECK(nanoamt_memberships_count(snapshot) == 1);
  nanoamt_memberships_free(snapshot);
  nanoamt_free(ga);
  nanoamt_free(gb);
  nanoamt_relay_free(r);
}
static void authentication(void) {
  unsigned random = 0;
  nanoamt_relay *r = new_relay(&random, 0);
  nanoamt_config config = fixture_config(&random);
  nanoamt_endpoint peer = peer_for(&config, 40000), rebound = peer_for(&config, 40001);
  nanoamt_datagram report;
  nanoamt *g = join(r, &config, &peer, 0, &report);
  nanoamt_relay_control control;
  CHECK(nanoamt_relay_receive(r, 1, &rebound, &config.discovery, report.bytes, report.size, &control) ==
        NANOAMT_IGNORED);
  for (size_t i = 2; i < 12; ++i) {
    report.bytes[i] ^= 1;
    CHECK(nanoamt_relay_receive(r, 1, &peer, &config.discovery, report.bytes, report.size, &control) ==
          NANOAMT_IGNORED);
    report.bytes[i] ^= 1;
  }
  nanoamt_relay_stats stats;
  nanoamt_relay_get_stats(r, &stats);
  CHECK(stats.clients == 1 && stats.bad_mac == 11);
  /* A spoofable Request cannot change a live client's ECN capability.
   * The capability becomes active only with its authenticated Update. */
  uint8_t ip[128], queued[128];
  size_t n = data(ip, &config, 5);
  ip[1] |= 2;
  ip_checksum(ip);
  nanoamt_relay_forward cursor;
  nanoamt_relay_output pending;
  CHECK(!nanoamt_relay_forward_begin(r, 1, ip, n, &cursor));
  CHECK(nanoamt_relay_forward_next(r, 1, &cursor, queued, sizeof(queued), &pending) == NANOAMT_PACKET);
  CHECK(pending.tos == 0);
  const uint8_t ecn_request[8] = {3, 2, 0, 0, 1, 2, 3, 4};
  CHECK(nanoamt_relay_receive(r, 1, &peer, &config.discovery, ecn_request, 8, &control) == NANOAMT_PACKET);
  CHECK(nanoamt_relay_output_valid(r, 1, &pending, queued, pending.size));
  memcpy(report.bytes + 2, control.bytes + 2, 10);
  CHECK(!nanoamt_relay_receive(r, 1, &peer, &config.discovery, report.bytes, report.size, &control));
  CHECK(!nanoamt_relay_output_valid(r, 1, &pending, queued, pending.size));
  CHECK(!nanoamt_relay_forward_begin(r, 1, ip, n, &cursor));
  CHECK(nanoamt_relay_forward_next(r, 1, &cursor, queued, sizeof(queued), &pending) == NANOAMT_PACKET);
  CHECK(pending.tos == 2);
  CHECK(!nanoamt_leave(g, 1));
  CHECK(nanoamt_send(g, 1, &report) == NANOAMT_PACKET);
  /* Authenticated Teardown is tied to its embedded endpoint, not new NAT port. */
  CHECK(!nanoamt_relay_receive(r, 1, &rebound, &config.discovery, report.bytes, report.size, &control));
  nanoamt_relay_get_stats(r, &stats);
  CHECK(!stats.clients && stats.teardowns == 1);
  nanoamt_free(g);
  nanoamt_relay_free(r);
  /* Cookie from the prior secret survives rotation for the overlap. */
  nanoamt_relay_config c = {0};
  c.random_bytes = fixture_random;
  c.random_context = &random;
  c.response_mac = test_mac;
  c.secret_interval_ms = 270000;
  r = nanoamt_relay_new(&c, 0);
  CHECK(r);
  config.direct = 1;
  g = join(r, &config, &peer, 269000, &report);
  CHECK(!nanoamt_relay_receive(r, 270000, &peer, &config.discovery, report.bytes, report.size, &control));
  CHECK(nanoamt_relay_receive(r, 540001, &peer, &config.discovery, report.bytes, report.size, &control) ==
        NANOAMT_IGNORED);
  nanoamt_free(g);
  nanoamt_relay_free(r);
}
static void mtu(void) {
  for (int inner6 = 0; inner6 < 2; ++inner6) {
    unsigned random = 0;
    nanoamt_relay *r = new_relay(&random, 0);
    nanoamt_config config = fixture_dual_config(&random, 0, inner6, 0);
    nanoamt_endpoint peer = peer_for(&config, 40000);
    nanoamt_datagram report;
    nanoamt *g = join(r, &config, &peer, 0, &report);
    CHECK(!nanoamt_relay_set_path_mtu(r, 0, &peer, &config.discovery, 576));
    uint8_t ip[4096], bytes[4096];
    size_t n = data(ip, &config, 2000);
    nanoamt_relay_forward cursor;
    nanoamt_relay_output out;
    CHECK(!nanoamt_relay_forward_begin(r, 0, ip, n, &cursor));
    nanoamt_packet packet;
    unsigned fragments = 0, delivered = 0;
    int rc;
    while ((rc = nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out)) == NANOAMT_PACKET) {
      if (inner6) {
        CHECK(out.kind == NANOAMT_RELAY_MTU_FEEDBACK && out.mtu == 546 && out.size == n);
        CHECK(!memcmp(bytes, ip, n));
      } else {
        CHECK(out.kind == NANOAMT_RELAY_DATA && out.size <= 548);
        CHECK(nanoamt_relay_output_valid(r, 0, &out, bytes, out.size));
        int received = nanoamt_receive(g, 0, &out.source, bytes, out.size, &packet);
        CHECK(received == NANOAMT_PACKET || received == NANOAMT_IGNORED);
        if (received == NANOAMT_PACKET) {
          CHECK(packet.size == 2000 && !memcmp(packet.data, ip + 28, 2000));
          ++delivered;
        }
        ++fragments;
      }
    }
    CHECK(rc == NANOAMT_OK);
    CHECK(inner6 ? !fragments && !delivered : fragments > 1 && delivered == 1);
    if (!inner6) {
      /* First fragment keeps all options; later fragments keep only copied
       * options. Independent gateway reassembly validates the final UDP data. */
      memmove(ip + 32, ip + 20, n - 20);
      n += 12;
      ip[0] = 0x48;
      memcpy(ip + 20, (uint8_t[]){0x44, 4, 4, 0, 0x94, 4, 0, 0, 1, 1, 0, 0}, 12);
      put16(ip + 2, (unsigned)n);
      ip_checksum(ip);
      CHECK(!nanoamt_relay_forward_begin(r, 1, ip, n, &cursor));
      fragments = delivered = 0;
      while ((rc = nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out)) == NANOAMT_PACKET) {
        CHECK(out.kind == NANOAMT_RELAY_DATA);
        size_t header = (bytes[2] & 15u) * 4u;
        CHECK(header == (fragments ? 24u : 32u));
        CHECK(!memcmp(bytes + 22 + (fragments ? 0 : 4), (uint8_t[]){0x94, 4, 0, 0}, 4));
        int received = nanoamt_receive(g, 1, &out.source, bytes, out.size, &packet);
        if (received == NANOAMT_PACKET) {
          CHECK(packet.size == 2000 && !memcmp(packet.data, ip + 40, 2000));
          ++delivered;
        } else
          CHECK(received == NANOAMT_IGNORED);
        ++fragments;
      }
      CHECK(rc == NANOAMT_OK && fragments > 1 && delivered == 1);
      put16(ip + 6, 0x4000);
      ip_checksum(ip);
      CHECK(!nanoamt_relay_forward_begin(r, 1, ip, n, &cursor));
      CHECK(nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
      CHECK(out.kind == NANOAMT_RELAY_MTU_FEEDBACK);
      CHECK(nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_OK);
    }
    nanoamt_free(g);
    nanoamt_relay_free(r);
  }
}
static void native_fragments(void) {
  for (int inner6 = 0; inner6 < 2; ++inner6) {
    unsigned random = 0;
    nanoamt_relay *r = new_relay(&random, 0);
    nanoamt_config config = fixture_dual_config(&random, 0, inner6, 0);
    nanoamt_endpoint peer = peer_for(&config, 40000);
    nanoamt_datagram report;
    nanoamt *g = join(r, &config, &peer, 0, &report);
    uint8_t original[128], fragment[128], bytes[128];
    data(original, &config, 5);
    size_t header = inner6 ? 40 : 20;
    nanoamt_packet packet;
    for (unsigned pass = 0; pass < 2; ++pass) {
      /* Native fragments arrive out of order, including a noninitial one. */
      size_t offset = pass ? 0 : 8, take = pass ? 8 : 5;
      memcpy(fragment, original, header);
      size_t n = header + take + (inner6 ? 8 : 0);
      if (inner6) {
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
      memcpy(fragment + header + (inner6 ? 8 : 0), original + header + offset, take);
      nanoamt_relay_forward cursor;
      nanoamt_relay_output out;
      CHECK(!nanoamt_relay_forward_begin(r, 0, fragment, n, &cursor));
      CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
      CHECK(out.size == n + 2 && !memcmp(bytes + 2, fragment, n));
      CHECK(nanoamt_relay_output_valid(r, 0, &out, bytes, out.size));
      int received = nanoamt_receive(g, 0, &out.source, bytes, out.size, &packet);
      CHECK(received == (pass ? NANOAMT_PACKET : NANOAMT_IGNORED));
      if (pass)
        CHECK(packet.size == 5 && !memcmp(packet.data, original + header + 8, 5));
      /* A nonfinal fragment with non-eight-byte-aligned data is invalid. */
      if (pass) {
        if (inner6)
          put16(fragment + 4, 15);
        else {
          put16(fragment + 2, (unsigned)n - 1);
          ip_checksum(fragment);
        }
        CHECK(nanoamt_relay_forward_begin(r, 0, fragment, n - 1, &cursor) == NANOAMT_IGNORED);
      }
    }
    /* Reject offsets that would exceed the maximum original IP payload. */
    memcpy(fragment, original, header);
    size_t n;
    if (inner6) {
      fragment[6] = 44;
      put16(fragment + 4, 21);
      memcpy(fragment + 40, (uint8_t[]){17, 0, 255, 248, 0, 0, 0, 77}, 8);
      memcpy(fragment + 48, original + 40, 13);
      n = 61;
    } else {
      put16(fragment + 2, 25);
      put16(fragment + 6, 0x1fff);
      memcpy(fragment + 20, original + 20, 5);
      ip_checksum(fragment);
      n = 25;
    }
    nanoamt_relay_forward cursor;
    CHECK(nanoamt_relay_forward_begin(r, 0, fragment, n, &cursor) == NANOAMT_IGNORED);
    nanoamt_free(g);
    nanoamt_relay_free(r);
  }
}
static int deny(void *ctx, const nanoamt_endpoint *peer, const nanoamt_memberships *requested,
                const nanoamt_memberships *aggregate) {
  (void)peer;
  CHECK(nanoamt_memberships_count(requested) == nanoamt_memberships_count(aggregate));
  return *(int *)ctx;
}
static void policy(void) {
  unsigned random = 0;
  int denied = 1;
  nanoamt_relay_config c = {0};
  c.random_bytes = fixture_random;
  c.random_context = &random;
  c.response_mac = test_mac;
  c.authorize = deny;
  c.authorize_context = &denied;
  nanoamt_relay *r = nanoamt_relay_new(&c, 0);
  CHECK(r);
  nanoamt_config config = fixture_config(&random);
  nanoamt_endpoint peer = peer_for(&config, 40000);
  nanoamt_datagram report;
  nanoamt *g = join(r, &config, &peer, 0, &report);
  nanoamt_memberships *snapshot;
  CHECK(!nanoamt_relay_snapshot(r, 0, &snapshot));
  CHECK(!nanoamt_memberships_count(snapshot));
  nanoamt_memberships_free(snapshot);
  denied = 0;
  nanoamt_relay_control out;
  CHECK(!nanoamt_relay_receive(r, 1, &peer, &config.discovery, report.bytes, report.size, &out));
  CHECK(!nanoamt_relay_snapshot(r, 1, &snapshot));
  CHECK(nanoamt_memberships_count(snapshot) == 1);
  nanoamt_memberships_free(snapshot);
  /* Denying a refresh preserves authorized interest, not a false failure. */
  denied = 1;
  CHECK(!nanoamt_relay_receive(r, 2, &peer, &config.discovery, report.bytes, report.size, &out));
  CHECK(!nanoamt_relay_snapshot(r, 2, &snapshot));
  CHECK(nanoamt_memberships_count(snapshot) == 1);
  nanoamt_memberships_free(snapshot);
  nanoamt_free(g);
  nanoamt_relay_free(r);
}
static void expiry(void) {
  unsigned random = 0;
  nanoamt_relay *r = new_relay(&random, 1);
  nanoamt_config config = fixture_config(&random);
  nanoamt_endpoint peer = peer_for(&config, 40000);
  nanoamt_datagram report;
  nanoamt *g = join(r, &config, &peer, 0, &report);
  CHECK(nanoamt_relay_next_timeout(r) == 260000);
  CHECK(nanoamt_relay_tick(r, -1) == NANOAMT_ERROR_ARGUMENT);
  CHECK(nanoamt_relay_tick(r, INT64_MAX) == NANOAMT_ERROR_ARGUMENT);
  CHECK(!nanoamt_relay_tick(r, 260000));
  nanoamt_relay_stats stats;
  nanoamt_relay_get_stats(r, &stats);
  CHECK(stats.clients == 0 && stats.expired == 1);
  nanoamt_memberships *snapshot;
  CHECK(!nanoamt_relay_snapshot(r, 260000, &snapshot));
  CHECK(!nanoamt_memberships_count(snapshot));
  nanoamt_memberships_free(snapshot);
  nanoamt_free(g);
  nanoamt_relay_free(r);
}
static void interface_refresh(void) {
  for (int outer6 = 0; outer6 < 2; ++outer6) {
    unsigned random = 0;
    nanoamt_relay *r = new_relay(&random, 1);
    nanoamt_config config = fixture_dual_config(&random, outer6, 0, 0);
    nanoamt_endpoint peer = peer_for(&config, 40000);
    config.discovery.scope_id = 7;
    nanoamt_datagram report;
    nanoamt *g = join(r, &config, &peer, 0, &report);
    uint8_t ip[128], bytes[128];
    size_t n = data(ip, &config, 5);
    nanoamt_relay_forward cursor;
    nanoamt_relay_output out;
    CHECK(!nanoamt_relay_forward_begin(r, 0, ip, n, &cursor));
    CHECK(nanoamt_relay_forward_next(r, 0, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
    CHECK(out.source.scope_id == 7 && nanoamt_relay_output_valid(r, 0, &out, bytes, out.size));
    nanoamt_relay_control reply;
    config.discovery.scope_id = 8;
    CHECK(!nanoamt_relay_receive(r, 1, &peer, &config.discovery, report.bytes, report.size, &reply));
    CHECK(!nanoamt_relay_output_valid(r, 1, &out, bytes, out.size));
    nanoamt_relay_stats stats;
    nanoamt_relay_get_stats(r, &stats);
    CHECK(stats.clients == 1);
    CHECK(!nanoamt_relay_forward_begin(r, 1, ip, n, &cursor));
    CHECK(nanoamt_relay_forward_next(r, 1, &cursor, bytes, sizeof(bytes), &out) == NANOAMT_PACKET);
    CHECK(out.source.scope_id == 8 && nanoamt_relay_output_valid(r, 1, &out, bytes, out.size));
    nanoamt_free(g);
    nanoamt_relay_free(r);
  }
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "exchange"))
    exchange();
  else if (!strcmp(argv[1], "fanout"))
    fanout();
  else if (!strcmp(argv[1], "authentication"))
    authentication();
  else if (!strcmp(argv[1], "mtu"))
    mtu();
  else if (!strcmp(argv[1], "native-fragments"))
    native_fragments();
  else if (!strcmp(argv[1], "policy"))
    policy();
  else if (!strcmp(argv[1], "expiry"))
    expiry();
  else if (!strcmp(argv[1], "interface-refresh"))
    interface_refresh();
  else
    CHECK(0);
  printf("===AMT relay %s OK===\n", argv[1]);
  return 0;
}
