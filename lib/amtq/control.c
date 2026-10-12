#include "internal.h"

int amtq_control_feed(amtq_control_reader *r, const uint8_t *p, size_t n, size_t *consumed,
                      int (*handle)(void *, uint64_t, uint8_t *, size_t), void *context) {
  if (!r || (!p && n) || !consumed || !handle)
    return NANOAMTQ_ERROR_ARGUMENT;
  *consumed = 0;
  while (n) {
    if (!r->target) {
      if (r->size == 16)
        return NANOAMTQ_ERROR_PROTOCOL;
      r->bytes[r->size++] = *p++;
      ++*consumed;
      --n;
      uint64_t type;
      size_t len, header;
      int rc = amtq_header(r->bytes, r->size, &type, &len, &header);
      if (rc == NANOAMTQ_INCOMPLETE)
        continue;
      if (rc)
        return rc;
      r->target = header + len;
    }
    size_t take = r->target - r->size;
    if (take > n)
      take = n;
    if (take) {
      memcpy(r->bytes + r->size, p, take);
      p += take;
      n -= take;
      *consumed += take;
      r->size += take;
    }
    if (r->size == r->target) {
      nanoamtq_record record;
      size_t used;
      int rc = nanoamtq_record_decode(r->bytes, r->size, &record, &used);
      if (rc)
        return rc;
      r->size = r->target = 0;
      rc = handle(context, record.type, r->bytes + used - record.size, record.size);
      if (rc)
        return rc; /* Caller retains the unconsumed suffix across a pause. */
    }
  }
  return NANOAMTQ_OK;
}
static int compare_ids(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
int amtq_settings_decode(const uint8_t *p, size_t n, int sender_relay, uint64_t *modes, uint64_t *preferred) {
  if ((!p && n) || !modes || !preferred || n > NANOAMTQ_MAX_CONTROL_VALUE)
    return NANOAMTQ_ERROR_ARGUMENT;
  *modes = 0;
  *preferred = UINT64_MAX;
  if (!n)
    return NANOAMTQ_ERROR_PROTOCOL;
  uint64_t *ids = malloc((n / 2 + 1) * sizeof(*ids));
  if (!ids)
    return NANOAMTQ_ERROR_MEMORY;
  size_t at = 0, count = 0;
  int valid = 1;
  while (at < n) {
    uint64_t id, value;
    if (!amtq_get(p, n, &at, &id) || !amtq_get(p, n, &at, &value)) {
      valid = 0;
      break;
    }
    ids[count++] = id;
    if (id == 0)
      *modes = value;
    if (id == 1) {
      *preferred = value;
      if (sender_relay)
        valid = 0;
    }
  }
  qsort(ids, count, sizeof(*ids), compare_ids);
  for (size_t i = 1; i < count; ++i)
    if (ids[i] == ids[i - 1])
      valid = 0;
  free(ids);
  if (!valid || !(*modes & 1u) ||
      (*preferred != UINT64_MAX && (*preferred > 61 || !(*modes & (UINT64_C(1) << *preferred)))))
    return NANOAMTQ_ERROR_PROTOCOL;
  return NANOAMTQ_OK;
}
