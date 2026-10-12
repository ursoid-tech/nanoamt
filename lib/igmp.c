#include "internal.h"

size_t nanoamt_general_query(uint8_t *ip, unsigned version, const uint8_t *source, uint8_t qqic, unsigned robustness,
                             uint32_t response_ms) {
  size_t header = version == 6 ? 48 : 24, body = version == 6 ? 28 : 12;
  memset(ip, 0, header + body);
  uint8_t *q = ip + header;
  if (version == 6) {
    ip[0] = 0x60;
    write16(ip + 4, (uint16_t)(8 + body));
    ip[7] = 1;
    if (source)
      memcpy(ip + 8, source, 16);
    ip[24] = 255;
    ip[25] = 2;
    ip[39] = 1;
    memcpy(ip + 40, (uint8_t[]){58, 0, 5, 2, 0, 0, 1, 0}, 8);
    q[0] = 130;
    /* Round upward to the representable MLD maximum response code. */
    unsigned code = response_ms;
    if (code >= 32768) {
      code = 0x8000;
      while (code < 65535) {
        uint32_t value = ((code & 4095u) | 4096u) << (((code >> 12) & 7u) + 3);
        if (value >= response_ms)
          break;
        ++code;
      }
    }
    write16(q + 4, (uint16_t)code);
    q[24] = (uint8_t)robustness;
    q[25] = qqic;
    ip_packet view = {0};
    view.version = 6;
    view.source = ip + 8;
    view.destination = ip + 24;
    write16(q + 2, nanoamt_checksum(q, body, nanoamt_pseudo_sum(&view, 58, body)));
  } else {
    ip[0] = 0x46;
    ip[1] = 0xc0;
    write16(ip + 2, (uint16_t)(header + body));
    ip[8] = 1;
    ip[9] = 2;
    if (source)
      memcpy(ip + 12, source, 4);
    ip[16] = 224;
    ip[19] = 1;
    ip[20] = 0x94;
    ip[21] = 4;
    write16(ip + 10, nanoamt_checksum(ip, header, 0));
    q[0] = 0x11;
    unsigned units = (response_ms + 99u) / 100u, code = units;
    if (units >= 128) {
      code = 128;
      while (code < 255 && (((code & 15u) | 16u) << (((code >> 4) & 7u) + 3)) < units)
        ++code;
    }
    q[1] = (uint8_t)code;
    q[8] = (uint8_t)robustness;
    q[9] = qqic;
    write16(q + 2, nanoamt_checksum(q, body, 0));
  }
  return header + body;
}

int nanoamt_query_decode(uint8_t *bytes, size_t size, unsigned version, uint32_t *interval_ms, unsigned *robustness) {
  ip_packet ip;
  static const uint8_t all_hosts[4] = {224, 0, 0, 1},
                       all_nodes[16] = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  if (!nanoamt_ip_decode(bytes, size, &ip) || ip.version != version || ip.ttl != 1)
    return 0;
  uint8_t *q = ip.payload;
  size_t offset;
  if (ip.version == 4) {
    if (ip.protocol != 2 || ip.payload_size < 12 || memcmp(ip.destination, all_hosts, 4) || q[0] != 0x11 ||
        !zero(q + 4, 4) || read16(q + 10) || nanoamt_checksum(q, ip.payload_size, 0))
      return 0;
    offset = 8;
  } else {
    if (ip.protocol != 58 || ip.payload_size < 28 || !ip.router_alert || memcmp(ip.destination, all_nodes, 16) ||
        q[0] != 130 || q[1] || !zero(q + 8, 16) || read16(q + 26) ||
        nanoamt_checksum(q, ip.payload_size, nanoamt_pseudo_sum(&ip, 58, ip.payload_size)))
      return 0;
    offset = 24;
  }
  uint32_t qqic = q[offset + 1];
  if (qqic >= 128)
    qqic = ((qqic & 15) | 16) << (((qqic >> 4) & 7) + 3);
  *interval_ms = (qqic ? qqic : 125) * 1000;
  *robustness = (q[offset] & 7) ? (q[offset] & 7) : 2;
  return 1;
}

void nanoamt_report_encode(nanoamt_datagram *out, const nanoamt_config *config, const uint8_t mac[6],
                           const uint8_t nonce[4], enum report_type type) {
  enum {
    MODE_IS_INCLUDE = 1,
    MODE_IS_EXCLUDE,
    CHANGE_TO_INCLUDE,
    CHANGE_TO_EXCLUDE,
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES
  };
  uint8_t record_type;
  if (type == REPORT_CURRENT)
    record_type = config->any_source ? MODE_IS_EXCLUDE : MODE_IS_INCLUDE;
  else if (type == REPORT_JOIN)
    record_type = config->any_source ? CHANGE_TO_EXCLUDE : ALLOW_NEW_SOURCES;
  else
    record_type = config->any_source ? CHANGE_TO_INCLUDE : BLOCK_OLD_SOURCES;
  uint8_t *p = out->bytes, *ip = p + 12;
  memset(p, 0, NANOAMT_CONTROL_CAPACITY);
  p[0] = MEMBERSHIP_UPDATE;
  memcpy(p + 2, mac, 6);
  memcpy(p + 8, nonce, 4);
  size_t address_size = ip_address_size(config->ip_version);
  unsigned sources = config->any_source ? 0 : 1;
  size_t report_size = 8 + 4 + address_size * (1 + sources);
  if (config->ip_version == 6) {
    uint8_t *mld = ip + 48;
    ip[0] = 0x60;
    ip[7] = 1;
    write16(ip + 4, (uint16_t)(8 + report_size));
    ip[24] = 255;
    ip[25] = 2;
    ip[39] = 22;
    ip[40] = 58;
    ip[42] = 5;
    ip[43] = 2;
    ip[46] = 1;
    mld[0] = 143;
    write16(mld + 6, 1);
    mld[8] = record_type;
    write16(mld + 10, (uint16_t)sources);
    memcpy(mld + 12, config->group, 16);
    if (sources)
      memcpy(mld + 28, config->source, 16);
    ip_packet view = {0};
    view.version = 6;
    view.source = ip + 8;
    view.destination = ip + 24;
    write16(mld + 2, nanoamt_checksum(mld, report_size, nanoamt_pseudo_sum(&view, 58, report_size)));
    out->size = 12 + 48 + report_size;
    return;
  }
  uint8_t *igmp = ip + 24;
  out->size = 12 + 24 + report_size;
  ip[0] = 0x46; /* IPv4 + router alert */
  ip[1] = 0xc0;
  write16(ip + 2, (uint16_t)(24 + report_size));
  ip[8] = 1;
  ip[9] = 2;
  ip[16] = 224;
  ip[19] = 22;
  ip[20] = 0x94;
  ip[21] = 4;
  write16(ip + 10, nanoamt_checksum(ip, 24, 0));
  igmp[0] = 0x22;
  write16(igmp + 6, 1);
  igmp[8] = record_type;
  write16(igmp + 10, (uint16_t)sources);
  memcpy(igmp + 12, config->group, 4);
  if (sources)
    memcpy(igmp + 16, config->source, 4);
  write16(igmp + 2, nanoamt_checksum(igmp, report_size, 0));
}
