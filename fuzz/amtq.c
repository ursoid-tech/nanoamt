#include "nanoamt/amtq.h"
#include "../t/00util/fixtures.h"

int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size) {
  if (!size || size > 131072)
    return 0;
  nanoamtq_record record;
  nanoamtq_datagram datagram;
  size_t consumed;
  (void)nanoamtq_record_decode(bytes, size, &record, &consumed);
  (void)nanoamtq_datagram_decode(bytes, size, &datagram);
  unsigned random = 0;
  nanoamt_config c = fixture_dual_config(&random, 0, (bytes[0] & 2) != 0, 0);
  nanoamtq_config config = {0};
  config.ip_version = c.ip_version;
  config.random_bytes = fixture_random;
  config.random_context = &random;
  config.max_incomplete = 2;
  nanoamtq *g = nanoamtq_new(&config, 0);
  if (!g)
    return 0;
  nanoamtq_membership membership = {0};
  memcpy(membership.source, c.source, 16);
  memcpy(membership.group, c.group, 16);
  (void)nanoamtq_set_memberships(g, &membership, 1);
  nanoamtq_control out;
  if (bytes[0] & 1) {
    (void)nanoamtq_send(g, 0, &out);
    const uint8_t settings[] = {0, 2, 0, 1};
    (void)nanoamtq_receive_control(g, 0, 0, settings, sizeof(settings), 0);
    (void)nanoamtq_send(g, 0, &out);
    (void)nanoamtq_record_decode(out.bytes, out.size, &record, &consumed);
    nanoamt_datagram request = {0};
    memcpy(request.bytes, record.data, record.size);
    uint8_t query[256], encoded[300];
    size_t n = fixture_dual_query(query, &request, &c, 125, 0), encoded_size;
    memset(query + 2, 0, 6);
    record = (nanoamtq_record){1, query, n};
    (void)nanoamtq_record_encode(&record, encoded, sizeof(encoded), &encoded_size);
    (void)nanoamtq_receive_control(g, 0, 0, encoded, encoded_size, 0);
    (void)nanoamtq_send(g, 0, &out);
    const uint8_t context[] = {2, 2, 0, 0};
    (void)nanoamtq_receive_control(g, 0, 0, context, sizeof(context), 0);
    (void)nanoamtq_send(g, 0, &out);
  }
  int64_t now = 0;
  for (size_t at = 1; at + 3 <= size && !nanoamtq_error(g);) {
    unsigned operation = bytes[at++];
    size_t n = (size_t)bytes[at] * 256 + bytes[at + 1];
    at += 2;
    if (n > size - at)
      n = size - at;
    const uint8_t *p = bytes + at;
    nanoamt_packet packet;
    switch (operation % 5) {
    case 0:
      (void)nanoamtq_receive_control(g, now, 0, p, n, 0);
      break;
    case 1:
      (void)nanoamtq_receive_datagram(g, now, p, n, &packet);
      break;
    case 2:
      (void)nanoamtq_set_memberships(g, n && (p[0] & 1) ? &membership : NULL, n && (p[0] & 1) ? 1 : 0);
      break;
    case 3:
      now += (int64_t)n;
      break;
    case 4:
      (void)nanoamtq_send(g, now, &out);
      break;
    }
    (void)nanoamtq_next_timeout(g);
    (void)nanoamtq_is_ready(g);
    at += n;
  }
  nanoamtq_free(g);
  return 0;
}
