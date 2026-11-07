#include "internal.h"

void amtq_frag_clear(amtq_fragment_slot *s) {
  free(s->data);
  free(s->starts);
  free(s->ends);
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
    s->starts = malloc(r->max_ranges * sizeof(*s->starts));
    s->ends = malloc(r->max_ranges * sizeof(*s->ends));
    if (!s->data || !s->starts || !s->ends) {
      amtq_frag_clear(s);
      return NANOAMTQ_IGNORED;
    }
    s->context = d->context_id;
    s->id = d->packet_id;
    s->total = d->total_size;
  }
  if (s->total != d->total_size)
    goto discard;
  size_t end = d->offset + d->size;
  for (unsigned i = 0; i < s->ranges; ++i) {
    if (s->starts[i] == d->offset && s->ends[i] == end) {
      if (memcmp(s->data + d->offset, d->data, d->size))
        goto discard;
      s->updated = now;
      return NANOAMTQ_IGNORED;
    }
    size_t low = s->starts[i] > d->offset ? s->starts[i] : d->offset;
    size_t high = s->ends[i] < end ? s->ends[i] : end;
    if (low < high && memcmp(s->data + low, d->data + (low - d->offset), high - low))
      goto discard;
  }
  if (s->ranges == r->max_ranges)
    goto discard;
  memcpy(s->data + d->offset, d->data, d->size);
  s->starts[s->ranges] = (uint32_t)d->offset;
  s->ends[s->ranges++] = (uint32_t)end;
  s->updated = now;
  for (size_t covered = 0; covered < s->total;) {
    size_t next = covered;
    for (unsigned i = 0; i < s->ranges; ++i)
      if (s->starts[i] <= covered && s->ends[i] > next)
        next = s->ends[i];
    if (next == covered)
      return NANOAMTQ_IGNORED;
    covered = next;
  }
  memcpy(out, s->data, s->total);
  amtq_frag_clear(s);
  return NANOAMTQ_PACKET;
discard:
  amtq_frag_clear(s);
  return NANOAMTQ_IGNORED;
}
