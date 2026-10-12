#include "nanoamt/relay.h"
#include "../t/00util/fixtures.h"

static int fuzz_mac(void *ctx, const uint8_t key[32], const uint8_t *p, size_t n, uint8_t out[6]) {
  (void)ctx;
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < 32; ++i)
    hash = (hash ^ key[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < n; ++i)
    hash = (hash ^ p[i]) * UINT64_C(1099511628211);
  for (size_t i = 0; i < 6; ++i) {
    out[i] = (uint8_t)hash;
    hash >>= 8;
  }
  return 0;
}
static void forward(nanoamt_relay *r, int64_t now, const uint8_t *p, size_t n) {
  nanoamt_relay_forward cursor;
  nanoamt_relay_output out;
  uint8_t bytes[65577];
  if (nanoamt_relay_forward_begin(r, now, p, n, &cursor))
    return;
  for (unsigned i = 0; i < 1024; ++i) {
    int rc = nanoamt_relay_forward_next(r, now, &cursor, bytes, sizeof(bytes), &out);
    if (rc != NANOAMT_PACKET)
      return;
    if (out.kind == NANOAMT_RELAY_DATA)
      CHECK(nanoamt_relay_output_valid(r, now, &out, bytes, out.size));
  }
  CHECK(0); /* Bounded clients and packet sizes must bound each fanout. */
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 65535)
    return 0;
  for (int mode = 0; mode < 4; ++mode) {
    unsigned random = 0;
    nanoamt_relay_config config = {0};
    config.random_bytes = fixture_random;
    config.random_context = &random;
    config.response_mac = fuzz_mac;
    config.max_clients = 8;
    config.memberships.max_groups = 4;
    config.memberships.max_sources = 32;
    config.memberships.max_sources_per_group = 16;
    nanoamt_relay *r = nanoamt_relay_new(&config, 0);
    if (!r)
      continue;
    nanoamt_config c = fixture_dual_config(&random, mode & 1, (mode >> 1) & 1, 0);
    c.direct = 1;
    nanoamt_endpoint peer = c.discovery;
    peer.port = 40000;
    nanoamt *g = nanoamt_new(&c, 0);
    CHECK(g);
    nanoamt_datagram request;
    nanoamt_relay_control response;
    nanoamt_packet packet;
    CHECK(nanoamt_send(g, 0, &request) == NANOAMT_PACKET);
    CHECK(nanoamt_relay_receive(r, 0, &peer, &c.discovery, request.bytes, request.size, &response) == NANOAMT_PACKET);
    uint8_t authentication[12];
    memcpy(authentication, response.bytes, sizeof(authentication));
    authentication[0] = 5;
    authentication[1] = 0;
    CHECK(nanoamt_receive(g, 0, &c.discovery, response.bytes, response.size, &packet) == NANOAMT_OK);
    CHECK(nanoamt_send(g, 0, &request) == NANOAMT_PACKET);
    CHECK(!nanoamt_relay_receive(r, 0, &peer, &c.discovery, request.bytes, request.size, &response));
    (void)nanoamt_relay_receive(r, 0, &peer, &c.discovery, data, size, &response);
    forward(r, 0, data, size);
    if (size > 2 && data[0] == 6)
      forward(r, 0, data + 2, size - 2);
    int64_t now = 0;
    for (size_t at = 0, operations = 0; size - at >= 3 && operations < 32; ++operations) {
      unsigned op = data[at++];
      size_t n = ((size_t)data[at] << 8) | data[at + 1];
      at += 2;
      if (n > size - at)
        n = size - at;
      const uint8_t *p = data + at;
      if (op % 5 == 0)
        (void)nanoamt_relay_receive(r, now, &peer, &c.discovery, p, n, &response);
      else if (op % 5 == 1) {
        uint8_t report[65547];
        memcpy(report, authentication, sizeof(authentication));
        memcpy(report + 12, p, n);
        (void)nanoamt_relay_receive(r, now, &peer, &c.discovery, report, n + 12, &response);
      } else if (op % 5 == 2)
        forward(r, now, p, n);
      else if (op % 5 == 3) {
        now += (int64_t)n * 100;
        (void)nanoamt_relay_tick(r, now);
      } else {
        nanoamt_memberships *snapshot = NULL;
        if (!nanoamt_relay_snapshot(r, now, &snapshot)) {
          CHECK(nanoamt_memberships_subset(snapshot, snapshot));
          nanoamt_memberships_free(snapshot);
        }
      }
      (void)nanoamt_relay_next_timeout(r);
      at += n;
    }
    nanoamt_free(g);
    nanoamt_relay_free(r);
    for (unsigned endpoint = 0; endpoint < 2; ++endpoint) {
      nanoamt_membership_config limits = {0};
      limits.mode = (uint8_t)endpoint;
      limits.max_groups = 4;
      limits.max_sources = 32;
      limits.max_sources_per_group = 16;
      nanoamt_memberships *s = nanoamt_memberships_new(&limits, 0);
      CHECK(s);
      int limited;
      (void)nanoamt_memberships_apply_limited(s, 0, data, size, c.ip_version == 6 ? 6 : 4, &limited);
      (void)nanoamt_memberships_tick(s, 260000);
      nanoamt_memberships_free(s);
    }
  }
  return 0;
}
