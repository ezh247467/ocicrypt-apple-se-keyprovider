#include "se_helper.h"

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

    // Lookup SE private key by tag
    const char *tagStr = "com.example.ecdhkey.default";
    CFStringRef tag = CFStringCreateWithCString(NULL, tagStr, kCFStringEncodingUTF8);
    CFDataRef tagData = CFStringCreateExternalRepresentation(NULL, tag, kCFStringEncodingUTF8, 0);
    CFRelease(tag);

    const void *queryKeys[] = { kSecClass, kSecAttrApplicationTag, kSecAttrKeyType, kSecReturnRef };
    const void *queryVals[] = { kSecClassKey, tagData, kSecAttrKeyTypeECSECPrimeRandom, kCFBooleanTrue };
    CFDictionaryRef query = CFDictionaryCreate(NULL, queryKeys, queryVals, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(tagData);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess || !result) return -4;
    SecKeyRef privKey = (SecKeyRef)result;

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

    memcpy(out, CFDataGetBytePtr(shared), len);
    *out_len = (size_t)len;
    CFRelease(shared);

    return 0;
}
