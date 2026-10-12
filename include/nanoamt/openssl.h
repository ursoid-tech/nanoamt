#ifndef NANOAMT_OPENSSL_H
#define NANOAMT_OPENSSL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Optional libnanoamt-openssl provider. Link -lnanoamt-openssl -lcrypto.
 * Directly assign these functions to the gateway/relay config callbacks.
 * context is unused. Success is zero; provider failure is -1. */
int nanoamt_openssl_random(void *context, void *bytes, size_t size);
int nanoamt_openssl_response_mac(void *context, const uint8_t key[32], const uint8_t *input, size_t size,
                                 uint8_t mac[6]);

#ifdef __cplusplus
}
#endif
#endif
