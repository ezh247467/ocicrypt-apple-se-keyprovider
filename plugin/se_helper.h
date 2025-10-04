#ifndef SE_HELPER_H
#define SE_HELPER_H
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int se_ecdh_shared_secret(const uint8_t *eph_pub, size_t eph_len,
                          uint8_t *out, size_t *out_len);
                          
#endif