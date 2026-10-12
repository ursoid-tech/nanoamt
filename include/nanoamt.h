#ifndef NANOAMT_H
#define NANOAMT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NANOAMT_PORT 2268
#define NANOAMT_CONTROL_CAPACITY 128

typedef struct nanoamt nanoamt;
typedef struct nanoamt_endpoint {
  uint8_t ip[16]; /* 4 octets for IPv4 */
  uint16_t port;
  uint8_t ip_version; /* 0/4: IPv4, 6: IPv6 */
  uint32_t scope_id;  /* IPv6 address scope; relay local endpoints also carry ingress interface index */
} nanoamt_endpoint;

typedef enum nanoamt_state {
  NANOAMT_STATE_DISCOVERING,
  NANOAMT_STATE_REQUESTING,
  NANOAMT_STATE_REPORTING,
  NANOAMT_STATE_JOINED,
  NANOAMT_STATE_LEAVING,
  NANOAMT_STATE_CLOSED,
  NANOAMT_STATE_FAILED
} nanoamt_state;

enum {
  NANOAMT_OK = 0,
  NANOAMT_PACKET = 1,
  NANOAMT_IGNORED = 2,
  NANOAMT_ERROR_ARGUMENT = -1,
  NANOAMT_ERROR_RANDOM = -2,
  NANOAMT_ERROR_TIMEOUT = -3
};

typedef struct nanoamt_config {
  nanoamt_endpoint discovery;
  uint8_t source[16];
  uint8_t group[16];
  uint16_t port; /* inner UDP port, 0 for any */
  int (*random_bytes)(void *context, void *bytes, size_t size);
  void *random_context;
  unsigned max_attempts;
  unsigned max_discoveries;
  uint32_t refresh_cap_ms;
  uint8_t ip_version; /* inner family, 0 for IPv4 */
  uint8_t any_source; /* ASM mode */
  uint8_t direct;     /* skip discovery */
  uint8_t ecn;        /* RFC 9601 */
} nanoamt_config;

typedef struct nanoamt_datagram {
  nanoamt_endpoint destination;
  size_t size;
  uint8_t bytes[NANOAMT_CONTROL_CAPACITY];
} nanoamt_datagram;

typedef struct nanoamt_packet {
  nanoamt_endpoint source, destination;
  uint8_t ttl, tos;
  uint8_t protocol;
  uint8_t *ip_data;
  size_t ip_size;
  uint8_t *data;
  size_t size;
} nanoamt_packet;

nanoamt *nanoamt_new(const nanoamt_config *config, int64_t now_ms);
void nanoamt_free(nanoamt *gateway);
nanoamt_state nanoamt_get_state(const nanoamt *gateway);
int nanoamt_is_joined(const nanoamt *gateway);

int64_t nanoamt_next_timeout(const nanoamt *gateway);

int nanoamt_send(nanoamt *gateway, int64_t now_ms, nanoamt_datagram *output);

int nanoamt_receive(nanoamt *gateway, int64_t now_ms, const nanoamt_endpoint *sender, uint8_t *bytes, size_t size,
                    nanoamt_packet *packet);

int nanoamt_receive_ecn(nanoamt *gateway, int64_t now_ms, const nanoamt_endpoint *sender, uint8_t *bytes, size_t size,
                        int outer_ecn, nanoamt_packet *packet);

int nanoamt_leave(nanoamt *gateway, int64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
