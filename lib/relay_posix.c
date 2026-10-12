#define _GNU_SOURCE
#include "nanoamt/relay_posix.h"
#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct queued_control {
  nanoamt_relay_control packet;
  int64_t at;
} queued_control;
typedef struct queued_input {
  uint8_t *bytes;
  size_t size;
  int64_t at;
  nanoamt_relay_forward cursor;
} queued_input;
typedef struct source_bucket {
  nanoamt_endpoint peer;
  uint64_t credit, used;
  int64_t at;
} source_bucket;
struct nanoamt_relay_posix {
  nanoamt_relay_posix_config config;
  nanoamt_relay *relay;
  nanoamt_endpoint bound;
  int fd, random_fd;
  queued_control *controls;
  queued_input *inputs;
  size_t control_head, control_count, input_head, input_count, input_bytes;
  nanoamt_relay_output pending;
  nanoamt_relay_forward before_pending;
  uint8_t output[65577], input[65536];
  int64_t now, rate_at;
  uint64_t rate_credit;
  source_bucket sources[64];
  uint64_t source_serial;
  nanoamt_relay_posix_stats stats;
};

static int relay_system_random(void *context, void *out, size_t size) {
  nanoamt_relay_posix *io = context;
  uint8_t *p = out;
  while (size) {
    ssize_t n = read(io->random_fd, p, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    p += n;
    size -= (size_t)n;
  }
  return 0;
}
static socklen_t relay_sockaddr(const nanoamt_endpoint *ep, struct sockaddr_storage *address) {
  memset(address, 0, sizeof(*address));
  if (ip_version(ep->ip_version) == 6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)address;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons(ep->port);
    a->sin6_scope_id = ep->scope_id;
    memcpy(&a->sin6_addr, ep->ip, 16);
    return sizeof(*a);
  }
  struct sockaddr_in *a = (struct sockaddr_in *)address;
  a->sin_family = AF_INET;
  a->sin_port = htons(ep->port);
  memcpy(&a->sin_addr, ep->ip, 4);
  return sizeof(*a);
}
static void relay_endpoint(const struct sockaddr_storage *address, nanoamt_endpoint *ep) {
  memset(ep, 0, sizeof(*ep));
  if (address->ss_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)address;
    ep->ip_version = 6;
    ep->port = ntohs(a->sin6_port);
    ep->scope_id = a->sin6_scope_id;
    memcpy(ep->ip, &a->sin6_addr, 16);
  } else {
    const struct sockaddr_in *a = (const struct sockaddr_in *)address;
    ep->ip_version = 4;
    ep->port = ntohs(a->sin_port);
    memcpy(ep->ip, &a->sin_addr, 4);
  }
}
static int relay_io_tick(nanoamt_relay_posix *io, int64_t now) {
  if (!io || now < io->now || now == INT64_MAX)
    return NANOAMT_ERROR_ARGUMENT;
  int rc = nanoamt_relay_tick(io->relay, now);
  if (!rc)
    io->now = now;
  return rc;
}

nanoamt_relay_posix *nanoamt_relay_posix_open(const nanoamt_relay_posix_config *config, int64_t now) {
#ifndef __linux__
  (void)config;
  (void)now;
  errno = ENOTSUP;
  return NULL;
#else
  if (!config || now < 0 || now == INT64_MAX ||
      (config->listen.ip_version && config->listen.ip_version != 4 && config->listen.ip_version != 6)) {
    errno = EINVAL;
    return NULL;
  }
  nanoamt_relay_posix *io = calloc(1, sizeof(*io));
  if (!io)
    return NULL;
  io->fd = io->random_fd = -1;
  io->config = *config;
  nanoamt_relay_posix_config *c = &io->config;
  if (!c->control_capacity)
    c->control_capacity = 32;
  if (!c->input_capacity)
    c->input_capacity = 8;
  if (!c->input_bytes)
    c->input_bytes = 1024 * 1024;
  if (!c->data_age_ms)
    c->data_age_ms = 1000;
  if (!c->control_age_ms)
    c->control_age_ms = 5000;
  if (!c->send_budget)
    c->send_budget = 64;
  if (!c->control_rate)
    c->control_rate = 1000;
  if (!c->control_burst)
    c->control_burst = 256;
  if (!c->source_rate)
    c->source_rate = 100;
  if (!c->source_burst)
    c->source_burst = 32;
  if (c->control_capacity > 1024 || c->input_capacity > 1024 || c->send_budget > 4096) {
    errno = EINVAL;
    goto fail;
  }
  io->now = io->rate_at = now;
  io->rate_credit = (uint64_t)c->control_burst * 1000;
  io->controls = calloc(c->control_capacity, sizeof(*io->controls));
  io->inputs = calloc(c->input_capacity, sizeof(*io->inputs));
  if (!io->controls || !io->inputs)
    goto fail;
  if (!c->relay.random_bytes) {
    io->random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (io->random_fd < 0)
      goto fail;
    c->relay.random_bytes = relay_system_random;
    c->relay.random_context = io;
  }
  io->relay = nanoamt_relay_new(&c->relay, now);
  if (!io->relay) {
    errno = EINVAL;
    goto fail;
  }
  int v6 = ip_version(c->listen.ip_version) == 6;
  io->fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (io->fd < 0)
    goto fail;
  int one = 1, pmtu = IP_PMTUDISC_DO;
  if (v6) {
    if (setsockopt(io->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) ||
        setsockopt(io->fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) ||
        setsockopt(io->fd, IPPROTO_IPV6, IPV6_RECVERR, &one, sizeof(one)) ||
        setsockopt(io->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof(one)))
      goto fail;
  } else if (setsockopt(io->fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) ||
             setsockopt(io->fd, IPPROTO_IP, IP_RECVERR, &one, sizeof(one)) ||
             setsockopt(io->fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu)))
    goto fail;
  struct sockaddr_storage address;
  socklen_t size = relay_sockaddr(&c->listen, &address);
  if (bind(io->fd, (struct sockaddr *)&address, size) || getsockname(io->fd, (struct sockaddr *)&address, &size))
    goto fail;
  relay_endpoint(&address, &io->bound);
  return io;
fail: {
  int error = errno;
  nanoamt_relay_posix_close(io);
  errno = error;
  return NULL;
}
#endif
}
void nanoamt_relay_posix_close(nanoamt_relay_posix *io) {
  if (!io)
    return;
  if (io->fd >= 0)
    close(io->fd);
  if (io->random_fd >= 0)
    close(io->random_fd);
  if (io->inputs)
    for (size_t i = 0; i < io->config.input_capacity; ++i)
      free(io->inputs[i].bytes);
  free(io->inputs);
  free(io->controls);
  nanoamt_relay_free(io->relay);
  free(io);
}
int nanoamt_relay_posix_fd(const nanoamt_relay_posix *io) {
  return io ? io->fd : -1;
}
void nanoamt_relay_posix_bound(const nanoamt_relay_posix *io, nanoamt_endpoint *ep) {
  if (io && ep)
    *ep = io->bound;
}
nanoamt_relay *nanoamt_relay_posix_core(nanoamt_relay_posix *io) {
  return io ? io->relay : NULL;
}

static int relay_take_credit(uint64_t *credit, int64_t *at, int64_t now, unsigned rate, unsigned burst) {
  uint64_t cap = (uint64_t)burst * 1000;
  uint64_t elapsed = (uint64_t)(now - *at), room = cap - *credit;
  *credit += elapsed >= (room + rate - 1) / rate ? room : elapsed * rate;
  *at = now;
  if (*credit < 1000)
    return 0;
  *credit -= 1000;
  return 1;
}
static int relay_source_credit(nanoamt_relay_posix *io, const nanoamt_endpoint *peer, int64_t now) {
  source_bucket *slot = &io->sources[0];
  int found = 0;
  for (size_t i = 0; i < 64; ++i) {
    source_bucket *bucket = &io->sources[i];
    if (bucket->used && ip_version(bucket->peer.ip_version) == ip_version(peer->ip_version) &&
        bucket->peer.scope_id == peer->scope_id &&
        !memcmp(bucket->peer.ip, peer->ip, ip_address_size(peer->ip_version))) {
      slot = bucket;
      found = 1;
      break;
    }
    if (bucket->used < slot->used)
      slot = bucket;
  }
  if (!found) {
    slot->peer = *peer;
    slot->at = now;
    slot->credit = (uint64_t)io->config.source_burst * 1000;
  }
  /* Saturation is practically unreachable; keep the table bounded even then. */
  if (io->source_serial != UINT64_MAX)
    ++io->source_serial;
  slot->used = io->source_serial;
  return relay_take_credit(&slot->credit, &slot->at, now, io->config.source_rate, io->config.source_burst);
}

static int relay_drain_errors(nanoamt_relay_posix *io) {
#ifdef __linux__
  /* Error payloads identify earlier datagrams, but accepting one at sendmsg
   * did not promise delivery. Drain bounded work even with no queued output,
   * so unreachable peers cannot leave the shared listener stuck at POLLERR. */
  for (unsigned i = 0; i < 32; ++i) {
    uint8_t byte;
    struct iovec vec = {&byte, 1};
    struct msghdr msg = {0};
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    ssize_t n;
    do {
      n = recvmsg(io->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      return NANOAMT_ERROR_IO;
    }
    ++io->stats.send_errors;
  }
  int error = 0;
  socklen_t size = sizeof(error);
  if (getsockopt(io->fd, SOL_SOCKET, SO_ERROR, &error, &size))
    return NANOAMT_ERROR_IO;
#else
  (void)io;
#endif
  return NANOAMT_OK;
}

int nanoamt_relay_posix_receive(nanoamt_relay_posix *io, int64_t now) {
  int rc = relay_io_tick(io, now);
  if (rc)
    return rc;
  rc = relay_drain_errors(io);
  if (rc)
    return rc;
#ifndef __linux__
  return NANOAMT_ERROR_IO;
#else
  struct sockaddr_storage address;
  struct iovec vec = {io->input, sizeof(io->input)};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } ancillary;
  struct msghdr msg = {0};
  msg.msg_name = &address;
  msg.msg_namelen = sizeof(address);
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = ancillary.bytes;
  msg.msg_controllen = sizeof(ancillary.bytes);
  ssize_t n;
  do {
    n = recvmsg(io->fd, &msg, 0);
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? NANOAMT_OK : NANOAMT_ERROR_IO;
  ++io->stats.received;
  if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || (address.ss_family != AF_INET && address.ss_family != AF_INET6)) {
    ++io->stats.truncated;
    return NANOAMT_IGNORED;
  }
  nanoamt_endpoint peer, local = io->bound;
  relay_endpoint(&address, &peer);
  if (!relay_take_credit(&io->rate_credit, &io->rate_at, now, io->config.control_rate, io->config.control_burst) ||
      !relay_source_credit(io, &peer, now)) {
    ++io->stats.rate_limited;
    return NANOAMT_IGNORED;
  }
  int found = 0;
  for (struct cmsghdr *h = CMSG_FIRSTHDR(&msg); h; h = CMSG_NXTHDR(&msg, h)) {
    if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO &&
        h->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
      struct in_pktinfo info;
      memcpy(&info, CMSG_DATA(h), sizeof(info));
      memcpy(local.ip, &info.ipi_addr, 4);
      local.scope_id = (uint32_t)info.ipi_ifindex;
      found = 1;
    }
    if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO &&
        h->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
      struct in6_pktinfo info;
      memcpy(&info, CMSG_DATA(h), sizeof(info));
      memcpy(local.ip, &info.ipi6_addr, 16);
      local.scope_id = info.ipi6_ifindex;
      found = 1;
    }
  }
  if (!found || !peer.port || !address_unicast(peer.ip, peer.ip_version) ||
      !address_unicast(local.ip, local.ip_version) || ip_version(peer.ip_version) != ip_version(local.ip_version))
    return NANOAMT_IGNORED;
  nanoamt_relay_control reply;
  rc = nanoamt_relay_receive(io->relay, now, &peer, &local, io->input, (size_t)n, &reply);
  if (rc != NANOAMT_PACKET)
    return rc;
  if (io->control_count == io->config.control_capacity) {
    ++io->stats.control_dropped;
    return NANOAMT_IGNORED;
  }
  size_t slot = (io->control_head + io->control_count++) % io->config.control_capacity;
  io->controls[slot].packet = reply;
  io->controls[slot].at = now;
  return NANOAMT_PACKET;
#endif
}

int nanoamt_relay_posix_forward(nanoamt_relay_posix *io, int64_t now, const uint8_t *ip, size_t size) {
  int rc = relay_io_tick(io, now);
  if (rc)
    return rc;
  if (!ip || !size || size > 65575)
    return NANOAMT_ERROR_ARGUMENT;
  if (io->input_count == io->config.input_capacity || size > io->config.input_bytes - io->input_bytes) {
    ++io->stats.input_dropped;
    return NANOAMT_RELAY_ERROR_LIMIT;
  }
  queued_input *work = &io->inputs[(io->input_head + io->input_count) % io->config.input_capacity];
  work->bytes = malloc(size);
  if (!work->bytes)
    return NANOAMT_RELAY_ERROR_MEMORY;
  memcpy(work->bytes, ip, size);
  rc = nanoamt_relay_forward_begin(io->relay, now, work->bytes, size, &work->cursor);
  if (rc) {
    free(work->bytes);
    work->bytes = NULL;
    return rc;
  }
  work->size = size;
  work->at = now;
  ++io->input_count;
  io->input_bytes += size;
  return NANOAMT_OK;
}

/* 1: accepted, 0: retry EAGAIN, -1: permanent datagram failure. */
static int relay_send_packet(nanoamt_relay_posix *io, const nanoamt_endpoint *source,
                             const nanoamt_endpoint *destination, const uint8_t *bytes, size_t size, uint8_t tos) {
#ifndef __linux__
  (void)io;
  (void)source;
  (void)destination;
  (void)bytes;
  (void)size;
  (void)tos;
  errno = ENOTSUP;
  return -1;
#else
  struct sockaddr_storage address;
  struct iovec vec = {(void *)bytes, size};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
  } ancillary;
  memset(&ancillary, 0, sizeof(ancillary));
  struct msghdr msg = {0};
  msg.msg_name = &address;
  msg.msg_namelen = relay_sockaddr(destination, &address);
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = ancillary.bytes;
  int v6 = ip_version(source->ip_version) == 6;
  size_t info_size = v6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo);
  msg.msg_controllen = CMSG_SPACE(info_size) + CMSG_SPACE(sizeof(int));
  struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
  h->cmsg_level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  h->cmsg_type = v6 ? IPV6_PKTINFO : IP_PKTINFO;
  h->cmsg_len = CMSG_LEN(info_size);
  if (v6) {
    struct in6_pktinfo info = {0};
    memcpy(&info.ipi6_addr, source->ip, 16);
    info.ipi6_ifindex = source->scope_id;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  } else {
    struct in_pktinfo info = {0};
    memcpy(&info.ipi_spec_dst, source->ip, 4);
    info.ipi_ifindex = (int)source->scope_id;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  }
  h = CMSG_NXTHDR(&msg, h);
  h->cmsg_level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  h->cmsg_type = v6 ? IPV6_TCLASS : IP_TOS;
  h->cmsg_len = CMSG_LEN(sizeof(int));
  int traffic = tos;
  memcpy(CMSG_DATA(h), &traffic, sizeof(traffic));
  ssize_t n;
  do {
    n = sendmsg(io->fd, &msg, 0);
  } while (n < 0 && errno == EINTR);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  if (n < 0 || (size_t)n != size) {
    ++io->stats.send_errors;
    return -1;
  }
  ++io->stats.sent;
  return 1;
#endif
}
/* Consult the kernel's route cache after EMSGSIZE. A connected probe carries
 * no application traffic and does not change the shared listener's peer. */
static int relay_reduce_mtu(nanoamt_relay_posix *io, const nanoamt_relay_output *out) {
#ifdef __linux__
  int v6 = ip_version(out->destination.ip_version) == 6;
  int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return 0;
  nanoamt_endpoint source = out->source;
  source.port = 0;
  struct sockaddr_storage local, peer;
  socklen_t local_size = relay_sockaddr(&source, &local);
  socklen_t peer_size = relay_sockaddr(&out->destination, &peer);
  int mtu = 0;
  socklen_t size = sizeof(mtu);
  /* Binding an address alone can select a different route on a multihomed
   * host. Match the packet-info interface used by relay_send_packet. These
   * Linux options take the interface index in network byte order and do not
   * require the privileges needed by SO_BINDTODEVICE. */
  uint32_t ifindex = htonl(source.scope_id);
  int rc = (source.scope_id && setsockopt(fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_UNICAST_IF : IP_UNICAST_IF,
                                          &ifindex, sizeof(ifindex))) ||
           bind(fd, (struct sockaddr *)&local, local_size) || connect(fd, (struct sockaddr *)&peer, peer_size) ||
           getsockopt(fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_MTU : IP_MTU, &mtu, &size);
  close(fd);
  if (!rc && mtu > 0 && (size_t)mtu < out->size + (v6 ? 48u : 28u) &&
      nanoamt_relay_set_path_mtu(io->relay, io->now, &out->destination, &out->source, (uint32_t)mtu) == NANOAMT_OK) {
    ++io->stats.path_mtu_updates;
    return 1;
  }
#else
  (void)io;
  (void)out;
#endif
  return 0;
}
static void relay_drop_input(nanoamt_relay_posix *io) {
  queued_input *work = &io->inputs[io->input_head];
  io->input_bytes -= work->size;
  free(work->bytes);
  memset(work, 0, sizeof(*work));
  io->input_head = (io->input_head + 1) % io->config.input_capacity;
  --io->input_count;
  memset(&io->pending, 0, sizeof(io->pending));
}
int nanoamt_relay_posix_send(nanoamt_relay_posix *io, int64_t now) {
  int rc = relay_io_tick(io, now), sent = 0;
  if (rc)
    return rc;
  rc = relay_drain_errors(io);
  if (rc)
    return rc;
  for (unsigned step = 0; step < io->config.send_budget; ++step) {
    if (io->control_count) {
      queued_control *control = &io->controls[io->control_head];
      if ((uint64_t)(now - control->at) >= io->config.control_age_ms)
        ++io->stats.expired;
      else {
        rc = relay_send_packet(io, &control->packet.source, &control->packet.destination, control->packet.bytes,
                               control->packet.size, 0);
        if (!rc)
          break;
        if (rc > 0)
          sent = 1;
      }
      io->control_head = (io->control_head + 1) % io->config.control_capacity;
      --io->control_count;
      continue;
    }
    if (!io->input_count)
      break;
    queued_input *work = &io->inputs[io->input_head];
    if ((uint64_t)(now - work->at) >= io->config.data_age_ms) {
      ++io->stats.expired;
      relay_drop_input(io);
      continue;
    }
    if (!io->pending.size) {
      io->before_pending = work->cursor;
      rc = nanoamt_relay_forward_next(io->relay, now, &work->cursor, io->output, sizeof(io->output), &io->pending);
      if (rc == NANOAMT_OK) {
        relay_drop_input(io);
        continue;
      }
      if (rc != NANOAMT_PACKET)
        return rc;
      if (io->pending.kind == NANOAMT_RELAY_MTU_FEEDBACK) {
        ++io->stats.mtu_feedback;
        if (io->config.mtu_feedback)
          io->config.mtu_feedback(io->config.feedback_context, now, io->output, io->pending.size, io->pending.mtu);
        memset(&io->pending, 0, sizeof(io->pending));
        continue;
      }
    }
    rc = nanoamt_relay_output_valid(io->relay, now, &io->pending, io->output, io->pending.size);
    if (rc < 0)
      return rc;
    if (!rc)
      ++io->stats.revoked;
    else {
      rc = relay_send_packet(io, &io->pending.source, &io->pending.destination, io->output, io->pending.size,
                             io->pending.tos);
      if (!rc)
        break;
      if (rc > 0)
        sent = 1;
      else if (errno == EMSGSIZE && relay_reduce_mtu(io, &io->pending)) {
        /* This datagram was not submitted. Reframe only this destination at
         * the reduced budget, preserving completed fanout and input age. */
        work->cursor = io->before_pending;
        work->cursor.feedback_done = 0;
      }
    }
    memset(&io->pending, 0, sizeof(io->pending));
  }
  return sent ? NANOAMT_PACKET : NANOAMT_OK;
}
int nanoamt_relay_posix_wants_write(const nanoamt_relay_posix *io) {
  return io && (io->control_count || io->input_count);
}
static int64_t relay_deadline(int64_t at, uint32_t age) {
  return at > INT64_MAX - age ? INT64_MAX : at + age;
}
int64_t nanoamt_relay_posix_next_timeout(const nanoamt_relay_posix *io) {
  if (!io)
    return INT64_MAX;
  int64_t next = nanoamt_relay_next_timeout(io->relay), deadline;
  if (io->control_count &&
      (deadline = relay_deadline(io->controls[io->control_head].at, io->config.control_age_ms)) < next)
    next = deadline;
  if (io->input_count && (deadline = relay_deadline(io->inputs[io->input_head].at, io->config.data_age_ms)) < next)
    next = deadline;
  return next;
}
void nanoamt_relay_posix_get_stats(const nanoamt_relay_posix *io, nanoamt_relay_posix_stats *stats) {
  if (!io || !stats)
    return;
  *stats = io->stats;
  stats->queued_controls = io->control_count;
  stats->queued_inputs = io->input_count;
  stats->retained_input_bytes = io->input_bytes;
}
