#include "internal.h"

uint16_t nanoamt_checksum(const uint8_t *bytes, size_t size, uint32_t sum) {
  while (size >= 2) {
    sum += read16(bytes);
    bytes += 2;
    size -= 2;
  }
  if (size != 0)
    sum += (uint32_t)*bytes << 8;
  while (sum >> 16)
    sum = (sum & 65535) + (sum >> 16);
  return (uint16_t)~sum;
}

static int ipv4_decode(uint8_t *bytes, size_t size, ip_packet *ip, int fragments) {
  if (size < 20 || bytes[0] >> 4 != 4)
    return 0;
  size_t header = (bytes[0] & 15u) * 4u, total = read16(bytes + 2);
  unsigned flags = read16(bytes + 6);
  if (header < 20 || header > size || total < header || total > size ||
      (flags & (fragments ? 0x8000u : 0xbfffu)) != 0 ||
      (fragments && ((flags & 0x3fffu) && ((flags & 0x4000u) || total == header))) ||
      (fragments && (flags & 0x2000u) && ((total - header) % 8)) ||
      (fragments && (flags & 0x1fffu) * 8u + total - header > 65515u) || nanoamt_checksum(bytes, header, 0) != 0)
    return 0;
  for (size_t i = 20; i < header;) {
    if (bytes[i] == 0)
      break;
    if (bytes[i] == 1) {
      ++i;
    } else {
      if (i + 1 >= header || bytes[i + 1] < 2 || bytes[i + 1] > header - i)
        return 0;
      if (bytes[i] == 0x94 && bytes[i + 1] == 4 && !read16(bytes + i + 2))
        ip->router_alert = 1;
      i += bytes[i + 1];
    }
  }
  ip->source = bytes + 12;
  ip->destination = bytes + 16;
  ip->protocol = bytes[9];
  ip->ttl = bytes[8];
  ip->tos = bytes[1];
  ip->size = total;
  ip->payload = bytes + header;
  ip->payload_size = total - header;
  return 1;
}

static int ip_decode(uint8_t *bytes, size_t size, ip_packet *ip, int fragments) {
  memset(ip, 0, sizeof(*ip));
  if (size < 1)
    return 0;
  ip->version = bytes[0] >> 4;
  if (ip->version == 4) {
    if (!ipv4_decode(bytes, size, ip, fragments))
      return 0;
  } else if (ip->version == 6) {
    if (size < 40)
      return 0;
    size_t total = 40u + read16(bytes + 4), at = 40;
    if (total > size)
      return 0;
    unsigned next = bytes[6];
    while (next == 0 || next == 60 || next == 43) {
      if (at + 8 > total || (next == 0 && at != 40))
        return 0;
      size_t length = ((size_t)bytes[at + 1] + 1) * 8;
      if (length > total - at)
        return 0;
      if (next == 43) {
        if (bytes[at + 3])
          return 0;
      } else {
        for (size_t option = at + 2; option < at + length;) {
          unsigned type = bytes[option];
          if (!type) {
            ++option;
            continue;
          }
          if (option + 2 > at + length || bytes[option + 1] > at + length - option - 2)
            return 0;
          if (type == 5) {
            if (bytes[option + 1] != 2)
              return 0;
            if (next == 0 && !read16(bytes + option + 2))
              ip->router_alert = 1;
          } else if (type & 0xc0)
            return 0;
          option += 2u + bytes[option + 1];
        }
      }
      next = bytes[at];
      at += length;
    }
    if (next == 44) {
      if (!fragments || at + 8 > total || bytes[at + 1] || (read16(bytes + at + 2) & 6u) ||
          ((read16(bytes + at + 2) & 0xfff9u) && total == at + 8) ||
          (read16(bytes + at + 2) & 0xfff8u) + total - at - 8 > 65535u - (at - 40) ||
          ((read16(bytes + at + 2) & 1u) && (total - at - 8) % 8))
        return 0;
      next = bytes[at];
      at += 8;
    }
    ip->size = total;
    ip->payload = bytes + at;
    ip->payload_size = total - at;
    ip->source = bytes + 8;
    ip->destination = bytes + 24;
    ip->protocol = (uint8_t)next;
    ip->ttl = bytes[7];
    ip->tos = (uint8_t)((bytes[0] << 4) | (bytes[1] >> 4));
  } else
    return 0;
  return 1;
}

int nanoamt_ip_decode(uint8_t *bytes, size_t size, ip_packet *ip) {
  return ip_decode(bytes, size, ip, 0);
}
int nanoamt_ip_forward_decode(const uint8_t *bytes, size_t size, ip_packet *ip) {
  return ip_decode((uint8_t *)bytes, size, ip, 1);
}

uint32_t nanoamt_pseudo_sum(const ip_packet *ip, uint8_t protocol, size_t size) {
  uint32_t sum = protocol + (uint32_t)size;
  size_t length = ip_address_size(ip->version);
  for (size_t i = 0; i < length; i += 2)
    sum += read16(ip->source + i) + read16(ip->destination + i);
  return sum;
}

int nanoamt_udp_decode(uint8_t *bytes, size_t size, const nanoamt_config *config, nanoamt_packet *packet) {
  ip_packet ip;
  size_t address_size = ip_address_size(config->ip_version);
  if (!nanoamt_ip_decode(bytes, size, &ip) || ip.version != config->ip_version ||
      (!config->any_source && memcmp(ip.source, config->source, address_size)) ||
      !address_unicast(ip.source, ip.version) || memcmp(ip.destination, config->group, address_size))
    return 0;
  uint8_t *payload = ip.payload;
  size_t payload_size = ip.payload_size;
  uint16_t source_port = 0, destination_port = 0;
  if (ip.protocol == 17) {
    if (payload_size < 8)
      return 0;
    size_t length = read16(payload + 4);
    if (length < 8 || length != payload_size || (config->port && read16(payload + 2) != config->port))
      return 0;
    if (read16(payload + 6) && nanoamt_checksum(payload, length, nanoamt_pseudo_sum(&ip, 17, length)))
      return 0;
    source_port = read16(payload);
    destination_port = read16(payload + 2);
    payload += 8;
    payload_size -= 8;
  } else if (config->port)
    return 0;
  memcpy(packet->source.ip, ip.source, address_size);
  memcpy(packet->destination.ip, ip.destination, address_size);
  packet->source.ip_version = packet->destination.ip_version = ip.version;
  packet->source.port = source_port;
  packet->destination.port = destination_port;
  packet->ttl = ip.ttl;
  packet->tos = ip.tos;
  packet->protocol = ip.protocol;
  packet->data = payload;
  packet->size = payload_size;
  packet->ip_data = bytes;
  packet->ip_size = ip.size;
  return 1;
}

void nanoamt_ecn_set(uint8_t *bytes, unsigned ecn) {
  if (bytes[0] >> 4 == 4) {
    bytes[1] = (uint8_t)((bytes[1] & 0xfcu) | ecn);
    write16(bytes + 10, 0);
    write16(bytes + 10, nanoamt_checksum(bytes, (bytes[0] & 15u) * 4u, 0));
  } else {
    bytes[1] = (uint8_t)((bytes[1] & 0xcfu) | (ecn << 4));
  }
}

int nanoamt_ecn_decapsulate(uint8_t *bytes, size_t size, unsigned outer) {
  unsigned inner;
  if (size >= 20 && bytes[0] >> 4 == 4) {
    size_t header = (bytes[0] & 15u) * 4u, total = read16(bytes + 2);
    if (header < 20 || header > total || total > size || nanoamt_checksum(bytes, header, 0))
      return 0;
    inner = bytes[1] & 3u;
  } else if (size >= 40 && bytes[0] >> 4 == 6) {
    if (40u + read16(bytes + 4) > size)
      return 0;
    inner = (bytes[1] >> 4) & 3u;
  } else
    return 0;
  /* RFC 6040 */
  static const int8_t result[4][4] = {{0, 0, 0, -1}, {1, 1, 1, 3}, {2, 1, 2, 3}, {3, 3, 3, 3}};
  int value = result[inner][outer];
  if (value < 0)
    return 0;
  if ((unsigned)value != inner)
    nanoamt_ecn_set(bytes, (unsigned)value);
  return 1;
}
