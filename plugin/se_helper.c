#include "se_helper.h"

/**
 * Generate ECDH shared secret using Secure Enclave private key and
 * the given ephemeral public key. Write the raw shared secret bytes
 * to out buffer.
 * 
 * @param eph_pub ephemeral public key bytes
 * @param eph_len ephemeral public key length
 * @param out raw shared secret output buffer
 * @param out_len length of output buffer (pointer), typically 32 bytes for AES-256
 * @return status code: 0 on success, otherwise error
 */
int se_ecdh_shared_secret(const uint8_t *eph_pub, size_t eph_len,
                          uint8_t *out, size_t *out_len) {
    if (!eph_pub || !out || !out_len) return -1;

    CFDataRef ephPubData = CFDataCreate(NULL, eph_pub, eph_len);
    if (!ephPubData) return -2;

    // Build SecKey attributes for ephemeral public key
    CFNumberRef keySize = CFNumberCreate(NULL, kCFNumberIntType, (int[]){256});
    const void *pubKeys[] = { kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits };
    const void *pubVals[] = { kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, keySize };
    CFDictionaryRef pubAttrs = CFDictionaryCreate(NULL, pubKeys, pubVals, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFErrorRef error = NULL;
    SecKeyRef ephKey = SecKeyCreateWithData(ephPubData, pubAttrs, &error);
    CFRelease(pubAttrs);
    CFRelease(ephPubData);
    CFRelease(keySize);

    if (!ephKey) return -3;

    // Prepare to lookup SE private key by tag
    const char *tag = "se.ocicrypt.default.tag";
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));

    const void *queryKeys[] = { kSecClass, kSecAttrApplicationTag, kSecAttrKeyType, kSecAttrKeyClass };
    const void *queryVals[] = { kSecClassKey, tagData, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPrivate };
    // kSecAttrTokenID, kSecAttrTokenIDSecureEnclave
    
    CFDictionaryRef query = CFDictionaryCreate(NULL, queryKeys, queryVals, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(tagData);

    // Query for the private key in Secure Enclave
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess || !result) return -4;
    SecKeyRef privKey = (SecKeyRef)result;

    // Derive shared secret from SE private key and eph public key
    CFDictionaryRef params = CFDictionaryCreate(
        kCFAllocatorDefault,
        NULL, NULL, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    // Perform ECDH inside Secure Enclave
    CFDataRef shared = SecKeyCopyKeyExchangeResult(privKey,
                    kSecKeyAlgorithmECDHKeyExchangeStandard,
                    ephKey, params, &error);
    CFRelease(ephKey);
    CFRelease(privKey);
    CFRelease(params);

    if (!shared) return -5;

    CFIndex len = CFDataGetLength(shared);
    if ((size_t)len > *out_len) {
        CFRelease(shared);
        return -6;
    }

    // Copy shared secret bytes to output buffer
    memcpy(out, CFDataGetBytePtr(shared), len);
    *out_len = (size_t)len;
    CFRelease(shared);

    return 0;
}
