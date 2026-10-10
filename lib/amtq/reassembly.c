#include "internal.h"

void amtq_frag_clear(amtq_fragment_slot *s) {
  free(s->data);
  free(s->seen);
  memset(s, 0, sizeof(*s));
}
void amtq_frag_expire(amtq_reassembly *r, int64_t now) {
  for (unsigned i = 0; i < r->capacity; ++i)
    if (r->slots[i].data && now - r->slots[i].updated >= r->timeout)
      amtq_frag_clear(&r->slots[i]);
}
void amtq_frag_discard(amtq_reassembly *r, uint64_t context) {
  for (unsigned i = 0; i < r->capacity; ++i)
    if (r->slots[i].data && r->slots[i].context == context)
      amtq_frag_clear(&r->slots[i]);
}
int64_t amtq_frag_deadline(const amtq_reassembly *r) {
  int64_t next = INT64_MAX;
  for (unsigned i = 0; i < r->capacity; ++i) {
    const amtq_fragment_slot *s = &r->slots[i];
    int64_t at = amtq_after(s->updated, r->timeout);
    if (s->data && at < next)
      next = at;
  }
  return next;
}
int amtq_frag_push(amtq_reassembly *r, int64_t now, const nanoamtq_datagram *d, uint8_t *out) {
  amtq_frag_expire(r, now);
  amtq_fragment_slot *s = NULL, *vacant = NULL, *oldest = &r->slots[0];
  for (unsigned i = 0; i < r->capacity; ++i) {
    amtq_fragment_slot *candidate = &r->slots[i];
    if (!candidate->data)
      vacant = candidate;
    else if (candidate->context == d->context_id && candidate->id == d->packet_id)
      s = candidate;
    if (candidate->updated < oldest->updated)
      oldest = candidate;
  }
  if (!s) {
    s = vacant ? vacant : oldest;
    amtq_frag_clear(s);
    s->data = malloc(d->total_size);
    s->seen = calloc((d->total_size + 7) / 8, 1);
    if (!s->data || !s->seen) {
      amtq_frag_clear(s);
      return NANOAMTQ_IGNORED;
    }
    s->context = d->context_id;
    s->id = d->packet_id;
    s->total = d->total_size;
  }
  if (s->total != d->total_size)
    goto discard;
  for (size_t i = 0; i < d->size; ++i) {
    size_t at = d->offset + i;
    if ((s->seen[at / 8] & (1u << (at % 8))) && s->data[at] != d->data[i])
      goto discard;
  }
  size_t end = d->offset + d->size;
  for (unsigned i = 0; i < s->ranges; ++i)
    if (s->starts[i] == d->offset && s->ends[i] == end) {
      s->updated = now;
      return NANOAMTQ_IGNORED;
    }
  if (s->ranges == r->max_ranges)
    goto discard;
  s->starts[s->ranges] = (uint32_t)d->offset;
  s->ends[s->ranges++] = (uint32_t)end;
  for (size_t i = 0; i < d->size; ++i) {
    size_t at = d->offset + i;
    if (!(s->seen[at / 8] & (1u << (at % 8)))) {
      s->seen[at / 8] |= (uint8_t)(1u << (at % 8));
      ++s->received;
    }
    s->data[at] = d->data[i];
  }
  s->updated = now;
  if (s->received != s->total)
    return NANOAMTQ_IGNORED;
  memcpy(out, s->data, s->total);
  amtq_frag_clear(s);
  return NANOAMTQ_PACKET;
discard:
  amtq_frag_clear(s);
  return NANOAMTQ_IGNORED;
}
