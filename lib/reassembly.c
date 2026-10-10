#include "internal.h"
#include <stdlib.h>

#define SLOTS 4
#define MAX_PREFIX 2048
#define MAX_BODY 65535

typedef struct fragment {
  uint8_t version, protocol, addresses[32], id[4];
  size_t prefix_size, previous_next, offset, length;
  const uint8_t *payload;
  unsigned ecn;
  int more;
} fragment;

typedef struct assembly {
  int used, first, final;
  int64_t created;
  uint8_t version, protocol, addresses[32], id[4];
  unsigned ecn_seen;
  size_t prefix_size, previous_next, total, received, highest;
  uint8_t prefix[MAX_PREFIX], body[MAX_BODY], seen[8192];
} assembly;

struct nanoamt_reassembly {
  assembly slots[SLOTS];
  uint8_t output[65575];
};

nanoamt_reassembly *nanoamt_reassembly_create(void) {
  return calloc(1, sizeof(nanoamt_reassembly));
}
void nanoamt_reassembly_destroy(nanoamt_reassembly *r) {
  free(r);
}

enum fragment_kind { INVALID_PACKET, WHOLE_PACKET, FRAGMENT_PACKET };

static enum fragment_kind parse_fragment(const uint8_t *p, size_t size, fragment *f) {
  memset(f, 0, sizeof(*f));
  if (size < 1)
    return INVALID_PACKET;
  f->version = p[0] >> 4;
  size_t prefix, total;
  if (f->version == 4) {
    if (size < 20)
      return INVALID_PACKET;
    prefix = (p[0] & 15u) * 4u;
    total = read16(p + 2);
    unsigned flags = read16(p + 6);
    if (prefix < 20 || prefix > total || total > size || (flags & 0x8000) || nanoamt_checksum(p, prefix, 0))
      return INVALID_PACKET;
    if (!(flags & 0x3fff))
      return WHOLE_PACKET;
    f->offset = (flags & 0x1fff) * 8u;
    f->more = (flags & 0x2000) != 0;
    f->protocol = p[9];
    memcpy(f->addresses, p + 12, 8);
    memcpy(f->id, p + 4, 2);
    f->payload = p + prefix;
    f->length = total - prefix;
    f->ecn = p[1] & 3u;
  } else if (f->version == 6) {
    if (size < 40)
      return INVALID_PACKET;
    total = 40u + read16(p + 4);
    if (total > size)
      return INVALID_PACKET;
    prefix = 40;
    f->previous_next = 6;
    unsigned next = p[6];
    while (next == 0 || next == 60 || next == 43) {
      if (prefix + 8 > total || (next == 0 && prefix != 40))
        return INVALID_PACKET;
      size_t extension = ((size_t)p[prefix + 1] + 1) * 8;
      if (extension > total - prefix)
        return INVALID_PACKET;
      f->previous_next = prefix;
      next = p[prefix];
      prefix += extension;
    }
    if (next != 44)
      return WHOLE_PACKET;
    if (prefix > MAX_PREFIX || prefix + 8 > total || p[prefix + 1] || (p[prefix + 3] & 6))
      return INVALID_PACKET;
    unsigned flags = read16(p + prefix + 2);
    f->offset = flags & 0xfff8u;
    f->more = flags & 1;
    f->protocol = p[prefix];
    memcpy(f->addresses, p + 8, 32);
    memcpy(f->id, p + prefix + 4, 4);
    f->payload = p + prefix + 8;
    f->length = total - prefix - 8;
    f->ecn = (p[1] >> 4) & 3u;
  } else
    return INVALID_PACKET;
  f->prefix_size = prefix;
  return FRAGMENT_PACKET;
}

static assembly *get_assembly(nanoamt_reassembly *r, int64_t now, const fragment *f) {
  assembly *slot = NULL, *oldest = &r->slots[0];
  for (size_t i = 0; i < SLOTS; ++i) {
    assembly *s = &r->slots[i];
    if (s->used && now - s->created >= 60000)
      s->used = 0;
    if (!s->used || (oldest->used && s->created < oldest->created))
      oldest = s;
    if (s->used && s->version == f->version && s->protocol == f->protocol &&
        !memcmp(s->addresses, f->addresses, sizeof(f->addresses)) && !memcmp(s->id, f->id, sizeof(f->id)))
      slot = s;
  }
  if (!slot) {
    slot = oldest;
    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    slot->created = now;
    slot->version = f->version;
    slot->protocol = f->protocol;
    memcpy(slot->addresses, f->addresses, sizeof(f->addresses));
    memcpy(slot->id, f->id, sizeof(f->id));
  }
  return slot;
}

static size_t finish_assembly(uint8_t *out, const assembly *s) {
  size_t total = s->prefix_size + s->total;
  if (total > (s->version == 4 ? 65535u : 65575u))
    return 0;
  memcpy(out, s->prefix, s->prefix_size);
  memcpy(out + s->prefix_size, s->body, s->total);
  if (s->version == 4) {
    write16(out + 2, (uint16_t)total);
    write16(out + 6, 0);
    write16(out + 10, 0);
    write16(out + 10, nanoamt_checksum(out, s->prefix_size, 0));
  } else {
    write16(out + 4, (uint16_t)(total - 40));
    out[s->previous_next] = s->protocol;
  }
  unsigned ecn = s->ecn_seen & 8 ? 3 : s->ecn_seen & 4 ? 2 : s->ecn_seen & 2 ? 1 : 0;
  nanoamt_ecn_set(out, ecn);
  return total;
}

int nanoamt_reassemble(nanoamt_reassembly *r, int64_t now, uint8_t **bytes, size_t *size) {
  fragment f;
  enum fragment_kind kind = parse_fragment(*bytes, *size, &f);
  if (kind != FRAGMENT_PACKET)
    return kind == WHOLE_PACKET;
  if (!f.offset && !f.more) { /* atomic fragment */
    memcpy(r->output, *bytes, f.prefix_size);
    memcpy(r->output + f.prefix_size, f.payload, f.length);
    r->output[f.previous_next] = f.protocol;
    write16(r->output + 4, (uint16_t)(f.prefix_size + f.length - 40));
    *bytes = r->output;
    *size = f.prefix_size + f.length;
    return 1;
  }
  size_t end = f.offset + f.length;
  if (!f.length || (f.more && (f.length & 7)) || end > MAX_BODY || f.prefix_size > MAX_PREFIX)
    return 0;
  assembly *slot = get_assembly(r, now, &f);
  if ((slot->final && (end > slot->total || (!f.more && end != slot->total))) || (!f.more && slot->highest > end))
    goto reject;
  slot->ecn_seen |= 1u << f.ecn;
  /* RFC 3168 */
  if ((slot->ecn_seen & 1) && slot->ecn_seen != 1)
    goto reject;
  for (size_t i = f.offset; i < end; ++i)
    if (slot->seen[i / 8] & (1u << (i % 8)))
      goto reject;
  for (size_t i = f.offset; i < end; ++i)
    slot->seen[i / 8] |= (uint8_t)(1u << (i % 8));
  memcpy(slot->body + f.offset, f.payload, f.length);
  slot->received += f.length;
  if (end > slot->highest)
    slot->highest = end;
  if (!f.more) {
    slot->final = 1;
    slot->total = end;
  }
  if (!f.offset) {
    slot->first = 1;
    slot->prefix_size = f.prefix_size;
    slot->previous_next = f.previous_next;
    memcpy(slot->prefix, *bytes, f.prefix_size);
  }
  if (!slot->first || !slot->final || slot->received != slot->total)
    return 0;
  slot->used = 0;
  size_t total = finish_assembly(r->output, slot);
  if (!total)
    return 0;
  *bytes = r->output;
  *size = total;
  return 1;
reject:
  slot->used = 0;
  return 0;
}
