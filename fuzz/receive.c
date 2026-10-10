#include "../t/00util/fixtures.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 65535)
    return 0;
  uint8_t *buffer = malloc(size + 1);
  if (!buffer)
    return 0;
  for (int mode = 0; mode < 4; ++mode) {
    int v6 = mode & 1;
    unsigned random = 0;
    nanoamt_config c = fixture_dual_config(&random, v6, v6, 0);
    c.ecn = (uint8_t)(mode >> 1);
    nanoamt *g = nanoamt_new(&c, 0);
    if (!g)
      continue;
    nanoamt_datagram out;
    nanoamt_packet packet;
    uint8_t control[256];
    memcpy(buffer, data, size);
    nanoamt_send(g, 0, &out);
    size_t n = fixture_advertisement(control, &out, &c.discovery);
    nanoamt_receive(g, 0, &c.discovery, buffer, size, &packet);
    nanoamt_receive(g, 1, &c.discovery, control, n, &packet);
    nanoamt_send(g, 1, &out);
    n = fixture_dual_query(control, &out, &c, 125, 1);
    nanoamt_receive(g, 2, &c.discovery, buffer, size, &packet);
    nanoamt_receive(g, 2, &c.discovery, control, n, &packet);
    nanoamt_send(g, 2, &out);
    nanoamt_receive_ecn(g, 3, &c.discovery, buffer, size, size ? buffer[size - 1] & 3 : 0, &packet);
    /* stream seed */
    if (size && buffer[0] == 0xf0) {
      size_t at = 1;
      for (unsigned i = 0; i < 16 && size - at >= 2; ++i) {
        n = ((size_t)buffer[at] << 8) | buffer[at + 1];
        at += 2;
        if (n > size - at)
          break;
        nanoamt_receive_ecn(g, 4 + i, &c.discovery, buffer + at, n, n ? buffer[at + n - 1] & 3 : 0, &packet);
        at += n;
      }
    }
    nanoamt_leave(g, 100);
    nanoamt_send(g, 100, &out);
    nanoamt_free(g);
  }
  free(buffer);
  return 0;
}
