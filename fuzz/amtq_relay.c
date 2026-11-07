#include "nanoamt/amtq_relay.h"
#include "../t/00util/fixtures.h"

static void feed(nanoamtq_relay *r, int64_t now, const uint8_t *p, size_t n) {
  for (unsigned records = 0; n && records < 1024 && !nanoamtq_relay_error(r); ++records) {
    size_t consumed;
    int rc = nanoamtq_relay_receive_control(r, now, 0, p, n, 0, &consumed);
    CHECK(consumed <= n);
    p += consumed;
    n -= consumed;
    if (rc == NANOAMTQ_MEMBERSHIP)
      (void)nanoamtq_relay_authorize_all(r, now, nanoamtq_relay_generation(r));
    else if (rc || !consumed)
      return;
  }
}
static void drive(nanoamtq *g, nanoamtq_relay *r, int64_t now) {
  for (unsigned i = 0; i < 64 && !nanoamtq_error(g) && !nanoamtq_relay_error(r); ++i) {
    nanoamtq_control out;
    int progress = 0;
    if (nanoamtq_send(g, now, &out) == NANOAMTQ_PACKET) {
      feed(r, now, out.bytes, out.size);
      progress = 1;
    }
    if (nanoamtq_relay_send(r, now, &out) == NANOAMTQ_PACKET) {
      (void)nanoamtq_receive_control(g, now, 0, out.bytes, out.size, 0);
      progress = 1;
    }
    if (!progress)
      return;
  }
}
static void forward(nanoamtq_relay *r, nanoamtq *g, int64_t now, uint64_t id, const uint8_t *p, size_t n,
                    size_t budget) {
  nanoamtq_relay_cursor cursor;
  if (nanoamtq_relay_datagram_begin(r, now, id, p, n, &cursor))
    return;
  uint8_t output[2048];
  nanoamtq_relay_datagram_output meta;
  for (unsigned i = 0; i < 65577; ++i) {
    int rc = nanoamtq_relay_datagram_next(r, now, &cursor, budget, output, sizeof(output), &meta);
    if (rc != NANOAMTQ_PACKET)
      return;
    CHECK(meta.size <= budget && nanoamtq_relay_datagram_valid(r, now, &meta, output, meta.size));
    nanoamt_packet packet;
    (void)nanoamtq_receive_datagram(g, now, output, meta.size, &packet);
  }
  CHECK(0);
}
int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size) {
  if (!size || size > 131072)
    return 0;
  unsigned random = 0;
  int v6 = bytes[0] & 1;
  nanoamt_config c = fixture_dual_config(&random, 0, v6, (bytes[0] & 2) != 0);
  nanoamtq_config gc = {0};
  gc.ip_version = c.ip_version;
  gc.random_bytes = fixture_random;
  gc.random_context = &random;
  gc.max_incomplete = 2;
  nanoamtq *g = nanoamtq_new(&gc, 0);
  nanoamtq_relay_config rc = {0};
  rc.connection_id = 1;
  rc.max_contexts = 4;
  rc.memberships.max_groups = 4;
  rc.memberships.max_sources = 16;
  rc.memberships.max_sources_per_group = 8;
  nanoamtq_relay *r = nanoamtq_relay_new(&rc, 0);
  CHECK(g && r);
  nanoamtq_membership m = {0};
  memcpy(m.source, c.source, 16);
  memcpy(m.group, c.group, 16);
  m.any_source = c.any_source;
  CHECK(!nanoamtq_set_memberships(g, &m, 1));
  drive(g, r, 0);
  CHECK(!nanoamtq_relay_open_context(r, 0, 0));
  drive(g, r, 0);
  CHECK(nanoamtq_is_ready(g) && nanoamtq_relay_is_ready(r));
  int64_t now = 0;
  for (size_t at = 1, operations = 0; size - at >= 3 && operations < 64 && !nanoamtq_relay_error(r); ++operations) {
    unsigned op = bytes[at++];
    size_t n = ((size_t)bytes[at] << 8) | bytes[at + 1];
    at += 2;
    if (n > size - at)
      n = size - at;
    const uint8_t *p = bytes + at;
    switch (op % 8) {
    case 0:
      feed(r, now, p, n);
      break;
    case 1:
      (void)nanoamtq_relay_receive_datagram(r, now, p, n);
      break;
    case 2:
      forward(r, g, now, 0, p, n, n ? 1u + p[0] * 5u : 1200u);
      break;
    case 3:
      m.source[v6 ? 15 : 3] = (uint8_t)(n ? p[0] : 10);
      (void)nanoamtq_set_memberships(g, n && (p[0] & 1) ? &m : NULL, n && (p[0] & 1) ? 1 : 0);
      drive(g, r, now);
      break;
    case 4:
      (void)nanoamtq_relay_open_context(r, now, n ? p[0] : 1);
      drive(g, r, now);
      break;
    case 5:
      (void)nanoamtq_relay_close_context(r, now, n ? p[0] : 0);
      drive(g, r, now);
      break;
    case 6:
      now += (int64_t)n * 10;
      (void)nanoamtq_relay_tick(r, now);
      break;
    case 7: {
      nanoamtq_authorization *token = NULL;
      uint64_t generation = nanoamtq_relay_generation(r);
      (void)nanoamtq_relay_prepare_authorization(r, now, generation, nanoamtq_relay_requested(r), &token);
      if (token)
        (void)nanoamtq_relay_commit_authorization(r, now, token);
      nanoamtq_relay_authorization_free(token);
      break;
    }
    }
    (void)nanoamtq_relay_next_timeout(r);
    at += n;
  }
  nanoamtq_free(g);
  nanoamtq_relay_free(r);
  return 0;
}
