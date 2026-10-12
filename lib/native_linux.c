#define _GNU_SOURCE
#include "nanoamt/native.h"
#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef struct native_filter {
  int fd;
  int reuse;
  struct group_filter *request;
  socklen_t size;
} native_filter;
struct nanoamt_native {
  nanoamt_native_config config;
  int fd, icmp4, icmp6, loopback;
  native_filter *filters;
  size_t count;
  uint8_t input[65575];
  int64_t feedback_at;
  uint64_t feedback_credit;
  nanoamt_native_stats stats;
};

static void native_address(struct sockaddr_storage *out, const uint8_t *ip, unsigned version, unsigned interface) {
  memset(out, 0, sizeof(*out));
  if (version == 6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
    a->sin6_family = AF_INET6;
    a->sin6_scope_id = interface;
    memcpy(&a->sin6_addr, ip, 16);
  } else {
    struct sockaddr_in *a = (struct sockaddr_in *)out;
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr, ip, 4);
  }
}
static void native_filters_free(native_filter *filters, size_t count) {
  if (!filters)
    return;
  for (size_t i = 0; i < count; ++i) {
    if (filters[i].fd >= 0)
      close(filters[i].fd);
    free(filters[i].request);
  }
  free(filters);
}
nanoamt_native *nanoamt_native_open(const nanoamt_native_config *config) {
  if (!config || !config->interface_index || config->interface_index > INT_MAX) {
    errno = EINVAL;
    return NULL;
  }
  nanoamt_native *n = calloc(1, sizeof(*n));
  if (!n)
    return NULL;
  n->fd = n->icmp4 = n->icmp6 = -1;
  n->config = *config;
  if (!n->config.max_groups)
    n->config.max_groups = 1024;
  if (!n->config.max_sources)
    n->config.max_sources = 4096;
  if (!n->config.feedback_rate)
    n->config.feedback_rate = 10;
  if (!n->config.feedback_burst)
    n->config.feedback_burst = 10;
  n->feedback_at = -1;
  n->feedback_credit = (uint64_t)n->config.feedback_burst * 1000;
  if (n->config.max_groups > 4096 || n->config.max_sources > 65536) {
    errno = EINVAL;
    goto fail;
  }
  char name[IF_NAMESIZE];
  if (!if_indextoname(config->interface_index, name))
    goto fail;
  n->fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (n->fd < 0)
    goto fail;
  struct ifreq request = {0};
  memcpy(request.ifr_name, name, strlen(name) + 1);
  if (ioctl(n->fd, SIOCGIFFLAGS, &request))
    goto fail;
  n->loopback = (request.ifr_flags & IFF_LOOPBACK) != 0;
  int one = 1;
  if (setsockopt(n->fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)))
    goto fail;
  /* SOCK_DGRAM packet sockets start at the network header. Reject unrelated
   * unicast/link traffic in the kernel before allocating receive-queue work. */
  struct sock_filter instructions[] = {BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
                                       BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
                                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 1, 0),
                                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 3, 5),
                                       BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 16),
                                       BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
                                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xe0, 3, 2),
                                       BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 24),
                                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xff, 1, 0),
                                       BPF_STMT(BPF_RET | BPF_K, 0),
                                       BPF_STMT(BPF_RET | BPF_K, UINT32_MAX)};
  struct sock_fprog program = {(unsigned short)(sizeof(instructions) / sizeof(instructions[0])), instructions};
  if (setsockopt(n->fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)))
    goto fail;
  struct sockaddr_ll address = {0};
  address.sll_family = AF_PACKET;
  address.sll_protocol = htons(ETH_P_ALL);
  address.sll_ifindex = (int)config->interface_index;
  if (bind(n->fd, (struct sockaddr *)&address, sizeof(address)))
    goto fail;
  return n;
fail: {
  int error = errno;
  nanoamt_native_close(n);
  errno = error;
  return NULL;
}
}
void nanoamt_native_close(nanoamt_native *n) {
  if (!n)
    return;
  if (n->fd >= 0)
    close(n->fd);
  if (n->icmp4 >= 0)
    close(n->icmp4);
  if (n->icmp6 >= 0)
    close(n->icmp6);
  native_filters_free(n->filters, n->count);
  free(n);
}
int nanoamt_native_fd(const nanoamt_native *n) {
  return n ? n->fd : -1;
}

static int native_install(native_filter *filter) {
  const struct group_filter *request = filter->request;
  int v6 = request->gf_group.ss_family == AF_INET6, level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  filter->fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (filter->fd < 0)
    return -1;
  if (request->gf_fmode == MCAST_INCLUDE) {
    if (!request->gf_numsrc) {
      errno = EINVAL;
      return -1;
    }
    struct group_source_req join = {0};
    join.gsr_interface = request->gf_interface;
    join.gsr_group = request->gf_group;
    join.gsr_source = request->gf_slist[0];
    if (setsockopt(filter->fd, level, MCAST_JOIN_SOURCE_GROUP, &join, sizeof(join)))
      return -1;
  } else {
    struct group_req join = {0};
    join.gr_interface = request->gf_interface;
    join.gr_group = request->gf_group;
    if (setsockopt(filter->fd, level, MCAST_JOIN_GROUP, &join, sizeof(join)))
      return -1;
  }
  return setsockopt(filter->fd, level, MCAST_MSFILTER, request, filter->size);
}
int nanoamt_native_reconcile(nanoamt_native *n, const nanoamt_memberships *aggregate) {
  if (!n || !aggregate)
    return NANOAMT_ERROR_ARGUMENT;
  size_t count = nanoamt_memberships_count(aggregate), sources = 0;
  if (count > n->config.max_groups)
    return NANOAMT_RELAY_ERROR_LIMIT;
  native_filter *prepared = count ? calloc(count, sizeof(*prepared)) : NULL;
  if (count && !prepared)
    return NANOAMT_RELAY_ERROR_MEMORY;
  for (size_t i = 0; i < count; ++i) {
    prepared[i].fd = -1;
    prepared[i].reuse = -1;
  }
  int rc = NANOAMT_OK;
  for (size_t i = 0; i < count; ++i) {
    nanoamt_membership_filter f;
    rc = nanoamt_memberships_get(aggregate, i, &f, NULL, 0);
    if (rc != NANOAMT_OK && rc != NANOAMT_RELAY_ERROR_BUFFER)
      goto fail;
    if (f.source_count > n->config.max_sources - sources) {
      rc = NANOAMT_RELAY_ERROR_LIMIT;
      goto fail;
    }
    sources += f.source_count;
    uint8_t (*addresses)[16] = f.source_count ? calloc(f.source_count, 16) : NULL;
    if (f.source_count && !addresses) {
      rc = NANOAMT_RELAY_ERROR_MEMORY;
      goto fail;
    }
    rc = nanoamt_memberships_get(aggregate, i, &f, addresses, f.source_count);
    if (rc) {
      free(addresses);
      goto fail;
    }
    size_t bytes = GROUP_FILTER_SIZE(f.source_count);
    struct group_filter *request = calloc(1, bytes);
    if (!request) {
      free(addresses);
      rc = NANOAMT_RELAY_ERROR_MEMORY;
      goto fail;
    }
    prepared[i].request = request;
    prepared[i].size = (socklen_t)bytes;
    request->gf_interface = n->config.interface_index;
    native_address(&request->gf_group, f.group, f.ip_version, request->gf_interface);
    request->gf_fmode = f.exclude ? MCAST_EXCLUDE : MCAST_INCLUDE;
    request->gf_numsrc = (uint32_t)f.source_count;
    for (size_t j = 0; j < f.source_count; ++j)
      native_address(&request->gf_slist[j], addresses[j], f.ip_version, request->gf_interface);
    free(addresses);
  }
  int unchanged = count == n->count;
  for (size_t i = 0; unchanged && i < count; ++i)
    unchanged =
        prepared[i].size == n->filters[i].size && !memcmp(prepared[i].request, n->filters[i].request, prepared[i].size);
  if (!unchanged) {
    for (size_t i = 0; i < count; ++i) {
      for (size_t j = 0; j < n->count; ++j)
        if (prepared[i].size == n->filters[j].size &&
            !memcmp(prepared[i].request, n->filters[j].request, prepared[i].size)) {
          prepared[i].reuse = (int)j;
          break;
        }
      if (prepared[i].reuse < 0 && native_install(&prepared[i])) {
        rc = NANOAMT_ERROR_IO;
        goto fail;
      }
    }
    for (size_t i = 0; i < count; ++i)
      if (prepared[i].reuse >= 0) {
        prepared[i].fd = n->filters[prepared[i].reuse].fd;
        n->filters[prepared[i].reuse].fd = -1;
      }
    native_filters_free(n->filters, n->count);
    n->filters = prepared;
    n->count = count;
    prepared = NULL;
    ++n->stats.transactions;
  }
  native_filters_free(prepared, count);
  n->stats.groups = count;
  n->stats.sources = sources;
  return NANOAMT_OK;
fail: {
  int error = errno;
  native_filters_free(prepared, count);
  ++n->stats.failed_transactions;
  errno = error;
  return rc;
}
}
int nanoamt_native_authorize(void *context, const nanoamt_endpoint *peer, const nanoamt_memberships *requested,
                             const nanoamt_memberships *aggregate) {
  (void)peer;
  (void)requested;
  return nanoamt_native_reconcile(context, aggregate);
}
static int native_fix_offload(uint8_t *bytes, size_t size) {
  ip_packet ip;
  if (!nanoamt_ip_decode(bytes, size, &ip))
    return 0; /* partial fragments cannot be repaired */
  uint8_t *transport = ip.payload;
  size_t checksum_at, length = ip.payload_size;
  uint32_t sum;
  if (ip.protocol == 17) {
    if (length < 8 || read16(transport + 4) < 8 || read16(transport + 4) > length)
      return 0;
    length = read16(transport + 4);
    checksum_at = 6;
    sum = nanoamt_pseudo_sum(&ip, 17, length);
  } else if (ip.protocol == 6) {
    if (length < 20 || (transport[12] >> 4) < 5 || (size_t)(transport[12] >> 4) * 4 > length)
      return 0;
    checksum_at = 16;
    sum = nanoamt_pseudo_sum(&ip, 6, length);
  } else if (ip.protocol == 58 || ip.protocol == 1) {
    if (length < 4 || (ip.protocol == 58 && ip.version != 6) || (ip.protocol == 1 && ip.version != 4))
      return 0;
    checksum_at = 2;
    sum = ip.protocol == 58 ? nanoamt_pseudo_sum(&ip, 58, length) : 0;
  } else
    return 0;
  write16(transport + checksum_at, 0);
  uint16_t checksum = nanoamt_checksum(transport, length, sum);
  write16(transport + checksum_at, ip.protocol == 17 && !checksum ? 65535 : checksum);
  return 1;
}
static const uint8_t *native_address_bytes(const struct sockaddr_storage *address) {
  return address->ss_family == AF_INET6 ? (const uint8_t *)&((const struct sockaddr_in6 *)address)->sin6_addr
                                        : (const uint8_t *)&((const struct sockaddr_in *)address)->sin_addr;
}
static int native_allows(const nanoamt_native *n, const ip_packet *ip) {
  size_t size = ip->version == 6 ? 16 : 4;
  for (size_t i = 0; i < n->count; ++i) {
    const struct group_filter *filter = n->filters[i].request;
    if ((filter->gf_group.ss_family == AF_INET6 ? 6 : 4) != ip->version ||
        memcmp(native_address_bytes(&filter->gf_group), ip->destination, size))
      continue;
    int listed = 0;
    for (size_t j = 0; j < filter->gf_numsrc; ++j)
      if (!memcmp(native_address_bytes(&filter->gf_slist[j]), ip->source, size)) {
        listed = 1;
        break;
      }
    return filter->gf_fmode == MCAST_EXCLUDE ? !listed : listed;
  }
  return 0;
}
int nanoamt_native_receive(nanoamt_native *n, nanoamt_native_packet *packet) {
  if (!n || !packet)
    return NANOAMT_ERROR_ARGUMENT;
  memset(packet, 0, sizeof(*packet));
  struct sockaddr_ll address = {0};
  struct iovec vec = {n->input, sizeof(n->input)};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
  } ancillary;
  struct msghdr msg = {0};
  msg.msg_name = &address;
  msg.msg_namelen = sizeof(address);
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = ancillary.bytes;
  msg.msg_controllen = sizeof(ancillary.bytes);
  ssize_t size;
  do {
    size = recvmsg(n->fd, &msg, 0);
  } while (size < 0 && errno == EINTR);
  if (size < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? NANOAMT_OK : NANOAMT_ERROR_IO;
  ++n->stats.captured;
  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
    ++n->stats.truncated;
    return NANOAMT_IGNORED;
  }
  if (address.sll_ifindex != (int)n->config.interface_index ||
      (address.sll_protocol != htons(ETH_P_IP) && address.sll_protocol != htons(ETH_P_IPV6)) ||
      (n->loopback && address.sll_pkttype == PACKET_OUTGOING)) {
    ++n->stats.filtered;
    return NANOAMT_IGNORED;
  }
  unsigned status = 0;
  int auxiliary = 0;
  for (struct cmsghdr *h = CMSG_FIRSTHDR(&msg); h; h = CMSG_NXTHDR(&msg, h))
    if (h->cmsg_level == SOL_PACKET && h->cmsg_type == PACKET_AUXDATA &&
        h->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {
      struct tpacket_auxdata data;
      memcpy(&data, CMSG_DATA(h), sizeof(data));
      status = data.tp_status;
      auxiliary = 1;
    }
  ip_packet ip;
  if (status & TP_STATUS_VLAN_VALID) {
    ++n->stats.filtered; /* subscribe/capture on the VLAN device, not its parent */
    return NANOAMT_IGNORED;
  }
  if (!auxiliary || !nanoamt_ip_forward_decode(n->input, (size_t)size, &ip) ||
      (ip.version == 4 ? ETH_P_IP : ETH_P_IPV6) != ntohs(address.sll_protocol)) {
    ++n->stats.malformed;
    return NANOAMT_IGNORED;
  }
  if (!multicast(ip.destination, ip.version) || !address_unicast(ip.source, ip.version) || !native_allows(n, &ip)) {
    ++n->stats.filtered;
    return NANOAMT_IGNORED;
  }
  if (status & TP_STATUS_CSUMNOTREADY) {
    if (!native_fix_offload(n->input, ip.size)) {
      ++n->stats.offload_dropped;
      return NANOAMT_IGNORED;
    }
    ++n->stats.offload_fixed;
  }
  packet->ip = n->input;
  packet->size = ip.size; /* exclude link padding */
  packet->interface_index = (uint32_t)address.sll_ifindex;
  packet->outgoing = address.sll_pkttype == PACKET_OUTGOING;
  return NANOAMT_PACKET;
}

void nanoamt_native_mtu_feedback(void *context, int64_t now, const uint8_t *bytes, size_t size, uint32_t mtu) {
  nanoamt_native *n = context;
  ip_packet ip;
  if (!n || !bytes || now < 0 || now == INT64_MAX || now < n->feedback_at ||
      !nanoamt_ip_forward_decode(bytes, size, &ip) || ip.size != size || !address_unicast(ip.source, ip.version))
    return;
  int ssm = ip.version == 4
                ? ip.destination[0] == 232
                : ip.destination[0] == 255 && (ip.destination[1] & 240u) == 48 && zero(ip.destination + 2, 2);
  int icmp_error = (ip.protocol == 58 && (!ip.payload_size || ip.payload[0] < 128)) ||
                   (ip.protocol == 1 && (!ip.payload_size || ip.payload[0] == 3 || ip.payload[0] == 4 ||
                                         ip.payload[0] == 5 || ip.payload[0] == 11 || ip.payload[0] == 12));
  if (!ssm || (ip.version == 4 && (mtu < 68 || mtu > 65535 || (read16(bytes + 6) & 0x1fffu))) ||
      (ip.version == 6 && !mtu) || icmp_error)
    return;
  uint64_t cap = (uint64_t)n->config.feedback_burst * 1000, room = cap - n->feedback_credit;
  uint64_t elapsed = n->feedback_at < 0 ? 0 : (uint64_t)(now - n->feedback_at);
  n->feedback_credit += elapsed >= (room + n->config.feedback_rate - 1) / n->config.feedback_rate
                            ? room
                            : elapsed * n->config.feedback_rate;
  n->feedback_at = now;
  if (n->feedback_credit < 1000) {
    ++n->stats.feedback_limited;
    return;
  }
  n->feedback_credit -= 1000;
  int v6 = ip.version == 6, *fd = v6 ? &n->icmp6 : &n->icmp4;
  if (*fd < 0)
    *fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
  if (*fd < 0) {
    ++n->stats.feedback_errors;
    return;
  }
  uint8_t output[1240] = {0};
  output[0] = v6 ? 2 : 3;
  output[1] = v6 ? 0 : 4;
  if (v6) {
    output[4] = (uint8_t)(mtu >> 24);
    output[5] = (uint8_t)(mtu >> 16);
    output[6] = (uint8_t)(mtu >> 8);
    output[7] = (uint8_t)mtu;
  } else
    write16(output + 6, (uint16_t)mtu);
  size_t quote = size < (v6 ? 1232u : 548u) ? size : (v6 ? 1232u : 548u);
  memcpy(output + 8, bytes, quote);
  if (!v6)
    write16(output + 2, nanoamt_checksum(output, quote + 8, 0));
  struct sockaddr_storage destination;
  native_address(&destination, ip.source, ip.version, n->config.interface_index);
  struct iovec vec = {output, quote + 8};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } ancillary;
  memset(&ancillary, 0, sizeof(ancillary));
  struct msghdr msg = {0};
  msg.msg_name = &destination;
  msg.msg_namelen = v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = ancillary.bytes;
  msg.msg_controllen = CMSG_SPACE(v6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo));
  struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
  h->cmsg_level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  h->cmsg_type = v6 ? IPV6_PKTINFO : IP_PKTINFO;
  h->cmsg_len = CMSG_LEN(v6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo));
  if (v6) {
    struct in6_pktinfo info = {0};
    info.ipi6_ifindex = n->config.interface_index;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  } else {
    struct in_pktinfo info = {0};
    info.ipi_ifindex = (int)n->config.interface_index;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  }
  ssize_t sent;
  do {
    sent = sendmsg(*fd, &msg, 0);
  } while (sent < 0 && errno == EINTR);
  if (sent < 0 || (size_t)sent != quote + 8)
    ++n->stats.feedback_errors;
  else
    ++n->stats.feedback_sent;
}
void nanoamt_native_get_stats(const nanoamt_native *n, nanoamt_native_stats *stats) {
  if (n && stats)
    *stats = n->stats;
}
