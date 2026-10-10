#include "internal.h"

size_t amtq_varint_size(uint64_t v) {
  return v < 64 ? 1 : v < 16384 ? 2 : v < UINT64_C(1073741824) ? 4 : 8;
}
size_t amtq_put(uint8_t *out, uint64_t v) {
  size_t n = amtq_varint_size(v);
  for (size_t i = n; i; --i) {
    out[i - 1] = (uint8_t)v;
    v >>= 8;
  }
  out[0] |= (uint8_t)(n == 1 ? 0 : n == 2 ? 0x40 : n == 4 ? 0x80 : 0xc0);
  return n;
}
int amtq_get(const uint8_t *p, size_t size, size_t *at, uint64_t *v) {
  if (*at >= size)
    return 0;
  size_t n = (size_t)1 << (p[*at] >> 6);
  if (n > size - *at)
    return 0;
  *v = p[*at] & 63u;
  for (size_t i = 1; i < n; ++i)
    *v = (*v << 8) | p[*at + i];
  *at += n;
  return 1;
}
int amtq_header(const uint8_t *p, size_t n, uint64_t *type, size_t *length, size_t *header) {
  size_t at = 0;
  uint64_t len;
  if (!amtq_get(p, n, &at, type) || !amtq_get(p, n, &at, &len))
    return NANOAMTQ_INCOMPLETE;
  if (len > NANOAMTQ_MAX_CONTROL_VALUE)
    return NANOAMTQ_ERROR_PROTOCOL;
  *length = (size_t)len;
  *header = at;
  return NANOAMTQ_OK;
}
int nanoamtq_record_decode(const uint8_t *p, size_t n, nanoamtq_record *record, size_t *consumed) {
  if (!record || !consumed || (!p && n))
    return NANOAMTQ_ERROR_ARGUMENT;
  memset(record, 0, sizeof(*record));
  *consumed = 0;
  uint64_t type;
  size_t len, header;
  int rc = amtq_header(p, n, &type, &len, &header);
  if (rc)
    return rc;
  if (len > n - header)
    return NANOAMTQ_INCOMPLETE;
  *record = (nanoamtq_record){type, p + header, len};
  *consumed = header + len;
  return NANOAMTQ_OK;
}
int nanoamtq_record_encode(const nanoamtq_record *r, uint8_t *p, size_t cap, size_t *size) {
  if (!r || !size || (!p && cap) || (!r->data && r->size) || r->type > AMTQ_VARINT_MAX ||
      r->size > NANOAMTQ_MAX_CONTROL_VALUE)
    return NANOAMTQ_ERROR_ARGUMENT;
  *size = amtq_varint_size(r->type) + amtq_varint_size(r->size) + r->size;
  if (cap < *size)
    return NANOAMTQ_ERROR_BUFFER;
  size_t at = amtq_put(p, r->type);
  at += amtq_put(p + at, r->size);
  if (r->size)
    memcpy(p + at, r->data, r->size);
  return NANOAMTQ_OK;
}
static int valid_data(const nanoamtq_datagram *d) {
  if (d->context_id > AMTQ_VARINT_MAX || d->format > AMTQ_VARINT_MAX || (!d->data && d->size))
    return 0;
  if (d->format == NANOAMTQ_COMPLETE)
    return d->size && d->size <= NANOAMTQ_MAX_DATA_MESSAGE;
  if (d->format == NANOAMTQ_FRAGMENT)
    return d->packet_id <= AMTQ_VARINT_MAX && d->total_size && d->total_size <= NANOAMTQ_MAX_DATA_MESSAGE &&
           d->offset < d->total_size && d->size && d->size <= d->total_size - d->offset;
  return 1;
}
int nanoamtq_datagram_decode(const uint8_t *p, size_t n, nanoamtq_datagram *d) {
  if (!d || (!p && n))
    return NANOAMTQ_ERROR_ARGUMENT;
  memset(d, 0, sizeof(*d));
  size_t at = 0;
  if (!amtq_get(p, n, &at, &d->format) || !amtq_get(p, n, &at, &d->context_id))
    return NANOAMTQ_ERROR_PROTOCOL;
  if (d->format == NANOAMTQ_FRAGMENT) {
    uint64_t total, offset;
    if (!amtq_get(p, n, &at, &d->packet_id) || !amtq_get(p, n, &at, &total) || !amtq_get(p, n, &at, &offset) ||
        total > NANOAMTQ_MAX_DATA_MESSAGE || offset > total)
      return NANOAMTQ_ERROR_PROTOCOL;
    d->total_size = (size_t)total;
    d->offset = (size_t)offset;
  }
  d->data = p + at;
  d->size = n - at;
  return valid_data(d) ? NANOAMTQ_OK : NANOAMTQ_ERROR_PROTOCOL;
}
int nanoamtq_datagram_encode(const nanoamtq_datagram *d, uint8_t *p, size_t cap, size_t *size) {
  if (!d || !size || (!p && cap) || !valid_data(d))
    return NANOAMTQ_ERROR_ARGUMENT;
  size_t header = amtq_varint_size(d->format) + amtq_varint_size(d->context_id);
  if (d->format == NANOAMTQ_FRAGMENT)
    header += amtq_varint_size(d->packet_id) + amtq_varint_size(d->total_size) + amtq_varint_size(d->offset);
  if (d->size > SIZE_MAX - header)
    return NANOAMTQ_ERROR_ARGUMENT;
  *size = header + d->size;
  if (cap < *size)
    return NANOAMTQ_ERROR_BUFFER;
  size_t at = amtq_put(p, d->format);
  at += amtq_put(p + at, d->context_id);
  if (d->format == NANOAMTQ_FRAGMENT) {
    at += amtq_put(p + at, d->packet_id);
    at += amtq_put(p + at, d->total_size);
    at += amtq_put(p + at, d->offset);
  }
  if (d->size)
    memcpy(p + at, d->data, d->size);
  return NANOAMTQ_OK;
}
