#ifndef NANOAMT_POSIX_H
#define NANOAMT_POSIX_H

#include "nanoamt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nanoamt_posix nanoamt_posix;
enum { NANOAMT_ERROR_IO = -4 };

nanoamt_posix *nanoamt_posix_open(const nanoamt_config *config, int64_t now_ms);
void nanoamt_posix_close(nanoamt_posix *io);
int nanoamt_posix_fd(const nanoamt_posix *io);
nanoamt_state nanoamt_posix_get_state(const nanoamt_posix *io);
int nanoamt_posix_is_joined(const nanoamt_posix *io);
int64_t nanoamt_posix_next_timeout(const nanoamt_posix *io);
int nanoamt_posix_wants_write(const nanoamt_posix *io);
int nanoamt_posix_send(nanoamt_posix *io, int64_t now_ms);
int nanoamt_posix_receive(nanoamt_posix *io, int64_t now_ms, nanoamt_packet *packet);
int nanoamt_posix_leave(nanoamt_posix *io, int64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
