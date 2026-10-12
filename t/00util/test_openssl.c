#include "fixtures.h"
#include "nanoamt/openssl.h"

int main(void) {
  /* RFC 4231 test case 1: extending a 20-byte key with zeros does not
   * change its HMAC-SHA256 block padding. Check the 48-bit AMT cookie. */
  uint8_t key[32] = {0}, mac[6], random[32];
  memset(key, 0x0b, 20);
  const uint8_t expected[6] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb};
  CHECK(!nanoamt_openssl_response_mac(NULL, key, (const uint8_t *)"Hi There", 8, mac));
  CHECK(!memcmp(mac, expected, 6));
  CHECK(!nanoamt_openssl_random(NULL, random, sizeof(random)));
  CHECK(!nanoamt_openssl_random(NULL, NULL, 0));
  CHECK(nanoamt_openssl_random(NULL, NULL, 1) == -1);
  CHECK(nanoamt_openssl_response_mac(NULL, NULL, NULL, 0, mac) == -1);
  CHECK(nanoamt_openssl_response_mac(NULL, key, NULL, 1, mac) == -1);
  puts("===AMT OpenSSL OK===");
  return 0;
}
