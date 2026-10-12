#include "nanoamt/openssl.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

int nanoamt_openssl_random(void *context, void *bytes, size_t size) {
  (void)context;
  uint8_t *p = bytes;
  if (!bytes && size)
    return -1;
  while (size) {
    int take = size > INT_MAX ? INT_MAX : (int)size;
    if (RAND_bytes(p, take) != 1)
      return -1;
    p += take;
    size -= (size_t)take;
  }
  return 0;
}
int nanoamt_openssl_response_mac(void *context, const uint8_t key[32], const uint8_t *input, size_t size,
                                 uint8_t mac[6]) {
  (void)context;
  if (!key || (!input && size) || !mac)
    return -1;
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned length = 0;
  int rc = -1;
  if (HMAC(EVP_sha256(), key, 32, input, size, digest, &length) && length == 32) {
    memcpy(mac, digest, 6);
    rc = 0;
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  return rc;
}
