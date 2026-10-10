#include "internal.h"

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
