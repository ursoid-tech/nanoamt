#define _POSIX_C_SOURCE 200809L
#include "nanoamt/posix.h"
#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct nanoamt_posix {
  nanoamt *gateway;
  int fd, random_fd, membership_sent;
  nanoamt_datagram output;
  uint8_t input[65536];
};

static int system_random(void *context, void *out, size_t size) {
  nanoamt_posix *io = context;
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

nanoamt_posix *nanoamt_posix_open(const nanoamt_config *config, int64_t now) {
  if (!config) {
    errno = EINVAL;
    return NULL;
  }
  nanoamt_posix *io = calloc(1, sizeof(*io));
  if (!io)
    return NULL;
  io->fd = io->random_fd = -1;
  nanoamt_config c = *config;
  if (!c.random_bytes) {
    io->random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (io->random_fd < 0)
      goto fail;
    c.random_bytes = system_random;
    c.random_context = io;
  }
  io->gateway = nanoamt_new(&c, now);
  if (!io->gateway) {
    errno = EINVAL;
    goto fail;
  }
  int family = ip_version(c.discovery.ip_version) == 6 ? AF_INET6 : AF_INET;
  io->fd = socket(family, SOCK_DGRAM, 0);
  if (io->fd < 0)
    goto fail;
  int flags = fcntl(io->fd, F_GETFL, 0);
  if (flags < 0 || fcntl(io->fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(io->fd, F_SETFD, FD_CLOEXEC) < 0)
    goto fail;
  struct sockaddr_storage local = {0};
  local.ss_family = (sa_family_t)family;
  socklen_t local_size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  if (family == AF_INET6) {
    int one = 1;
    if (setsockopt(io->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)))
      goto fail;
  }
  if (c.ecn) {
    int one = 1, level, option;
    if (family == AF_INET) {
#ifdef IP_RECVTOS
      level = IPPROTO_IP;
      option = IP_RECVTOS;
#else
      errno = ENOTSUP;
      goto fail;
#endif
    } else {
#ifdef IPV6_RECVTCLASS
      level = IPPROTO_IPV6;
      option = IPV6_RECVTCLASS;
#else
      errno = ENOTSUP;
      goto fail;
#endif
    }
    if (setsockopt(io->fd, level, option, &one, sizeof(one)))
      goto fail;
  }
  if (bind(io->fd, (struct sockaddr *)&local, local_size) != 0)
    goto fail;
  return io;
fail: {
  int error = errno;
  nanoamt_posix_close(io);
  errno = error;
  return NULL;
}
}

void nanoamt_posix_close(nanoamt_posix *io) {
  if (!io)
    return;
  if (io->fd >= 0)
    close(io->fd);
  if (io->random_fd >= 0)
    close(io->random_fd);
  nanoamt_free(io->gateway);
  free(io);
}

int nanoamt_posix_fd(const nanoamt_posix *io) {
  return io->fd;
}
nanoamt_state nanoamt_posix_get_state(const nanoamt_posix *io) {
  return nanoamt_get_state(io->gateway);
}
int nanoamt_posix_is_joined(const nanoamt_posix *io) {
  return io->membership_sent && nanoamt_is_joined(io->gateway);
}
int64_t nanoamt_posix_next_timeout(const nanoamt_posix *io) {
  return io->output.size ? INT64_MAX : nanoamt_next_timeout(io->gateway);
}
int nanoamt_posix_wants_write(const nanoamt_posix *io) {
  return io->output.size != 0;
}

int nanoamt_posix_send(nanoamt_posix *io, int64_t now) {
  if (!nanoamt_is_joined(io->gateway))
    io->membership_sent = 0;
  if (!io->output.size) {
    int ret = nanoamt_send(io->gateway, now, &io->output);
    if (ret != NANOAMT_PACKET)
      return ret;
  }
  struct sockaddr_storage to = {0};
  socklen_t to_size;
  if (io->output.destination.ip_version == 6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&to;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(io->output.destination.port);
    v6->sin6_scope_id = io->output.destination.scope_id;
    memcpy(&v6->sin6_addr, io->output.destination.ip, 16);
    to_size = sizeof(*v6);
  } else {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&to;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(io->output.destination.port);
    memcpy(&v4->sin_addr, io->output.destination.ip, 4);
    to_size = sizeof(*v4);
  }
  ssize_t n;
  do {
    n = sendto(io->fd, io->output.bytes, io->output.size, 0, (struct sockaddr *)&to, to_size);
  } while (n < 0 && errno == EINTR);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return NANOAMT_OK;
    return NANOAMT_ERROR_IO;
  }
  if ((size_t)n != io->output.size) {
    errno = EIO;
    return NANOAMT_ERROR_IO;
  }
  io->output.size = 0;
  if (io->output.bytes[0] == MEMBERSHIP_UPDATE && nanoamt_is_joined(io->gateway))
    io->membership_sent = 1;
  return NANOAMT_PACKET;
}

int nanoamt_posix_receive(nanoamt_posix *io, int64_t now, nanoamt_packet *packet) {
  if (!packet)
    return NANOAMT_ERROR_ARGUMENT;
  memset(packet, 0, sizeof(*packet));
  struct sockaddr_storage from = {0};
  struct iovec vec = {io->input, sizeof(io->input)};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(int)) * 2];
  } control;
  struct msghdr msg = {0};
  msg.msg_control = control.bytes;
  msg.msg_controllen = sizeof(control.bytes);
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  ssize_t n;
  do {
    n = recvmsg(io->fd, &msg, 0);
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? NANOAMT_OK : NANOAMT_ERROR_IO;
  if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || (from.ss_family != AF_INET && from.ss_family != AF_INET6))
    return NANOAMT_IGNORED;
  nanoamt_endpoint peer = {0};
  if (from.ss_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&from;
    memcpy(peer.ip, &v6->sin6_addr, 16);
    peer.port = ntohs(v6->sin6_port);
    peer.scope_id = v6->sin6_scope_id;
    peer.ip_version = 6;
  } else {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)&from;
    memcpy(peer.ip, &v4->sin_addr, 4);
    peer.port = ntohs(v4->sin_port);
  }
  int ecn = -1;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len >= CMSG_LEN(1))
      ecn = *(const uint8_t *)CMSG_DATA(cmsg) & 3;
#ifdef IPV6_TCLASS
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS && cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
      int value;
      memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
      ecn = value & 3;
    }
#endif
  }
  return nanoamt_receive_ecn(io->gateway, now, &peer, io->input, (size_t)n, ecn, packet);
}

int nanoamt_posix_leave(nanoamt_posix *io, int64_t now) {
  io->output.size = 0;
  return nanoamt_leave(io->gateway, now);
}
