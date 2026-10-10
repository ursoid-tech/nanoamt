#ifndef NANOAMT_AMTQ_INTERNAL_H
#define NANOAMT_AMTQ_INTERNAL_H
#include "nanoamt/amtq.h"
#include "../internal.h"
#include <limits.h>
#include <stdlib.h>

#define AMTQ_VARINT_MAX UINT64_C(0x3fffffffffffffff)
#define AMTQ_MAX_RANGES 1024U
size_t amtq_varint_size(uint64_t value);
size_t amtq_put(uint8_t *out, uint64_t value);
int amtq_get(const uint8_t *bytes, size_t size, size_t *at, uint64_t *value);
int amtq_header(const uint8_t *bytes, size_t size, uint64_t *type, size_t *length, size_t *header);

typedef struct amtq_fragment_slot {
  uint64_t context, id;
  int64_t updated;
  size_t total, received;
  unsigned ranges;
  uint32_t starts[AMTQ_MAX_RANGES], ends[AMTQ_MAX_RANGES];
  uint8_t *data, *seen;
} amtq_fragment_slot;
typedef struct amtq_reassembly {
  amtq_fragment_slot *slots;
  unsigned capacity, max_ranges;
  uint32_t timeout;
} amtq_reassembly;
void amtq_frag_clear(amtq_fragment_slot *slot);
void amtq_frag_expire(amtq_reassembly *r, int64_t now);
void amtq_frag_discard(amtq_reassembly *r, uint64_t context);
int64_t amtq_frag_deadline(const amtq_reassembly *r);
int amtq_frag_push(amtq_reassembly *r, int64_t now, const nanoamtq_datagram *d, uint8_t *output);
static inline int64_t amtq_after(int64_t now, uint32_t delay) {
  return now > INT64_MAX - delay ? INT64_MAX : now + delay;
}
#endif
