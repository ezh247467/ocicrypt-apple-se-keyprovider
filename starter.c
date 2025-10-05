// clang starter.c -o starter -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *DEFAULT_TAG = "se.ocicrypt.default.tag";

static SecKeyRef find_existing_key(const char *tag) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(query, kSecClass, kSecClassKey);
    CFDictionaryAddValue(query, kSecAttrApplicationTag, tagData);
    CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    // kSecAttrTokenID, kSecAttrTokenIDSecureEnclave

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);

    CFRelease(query);
    CFRelease(tagData);

    if (status == errSecSuccess) return key;
    return NULL;
}

static SecKeyRef create_new_key(const char *tag) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));

    CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(privAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(privAttrs, kSecAttrApplicationTag, tagData);

    int keySize = 256;
    CFNumberRef keySizeNum = CFNumberCreate(NULL, kCFNumberIntType, &keySize);

    const void *keys[] = { kSecAttrKeyType, kSecAttrKeySizeInBits, kSecPrivateKeyAttrs };
    const void *vals[] = { kSecAttrKeyTypeECSECPrimeRandom, keySizeNum, privAttrs };
    // kSecAttrTokenID, kSecAttrTokenIDSecureEnclave

    CFDictionaryRef params = CFDictionaryCreate(NULL, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFErrorRef error = NULL;
    SecKeyRef privKey = SecKeyCreateRandomKey(params, &error);
    if (!privKey) {
        CFStringRef errMsg = CFErrorCopyDescription(error);
        char buf[256];
        CFStringGetCString(errMsg, buf, sizeof(buf), kCFStringEncodingUTF8);
        fprintf(stderr, "Key creation failed: %s\n", buf);
        CFRelease(errMsg);
    }

    CFRelease(params);
    CFRelease(keySizeNum);
    CFRelease(privAttrs);
    CFRelease(tagData);
    if (error) CFRelease(error);

    return privKey;
}

int main(void) {
    const char *tag = DEFAULT_TAG;

    SecKeyRef privKey = find_existing_key(tag);
    if (privKey) {
        printf("Found existing Secure Enclave key for tag '%s'\n", tag);
    } else {
        printf("No key found, creating new one...\n");
        privKey = create_new_key(tag);
        if (!privKey) return 1;
    }

    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (!pubKey) {
        fprintf(stderr, "Failed to extract public key\n");
        CFRelease(privKey);
        return 1;
    }

    CFErrorRef error = NULL;
    CFDataRef pubData = SecKeyCopyExternalRepresentation(pubKey, &error);
    if (!pubData) {
        if (error) {
            CFStringRef errMsg = CFErrorCopyDescription(error);
            char buf[256];
            if (CFStringGetCString(errMsg, buf, sizeof(buf), kCFStringEncodingUTF8))
                fprintf(stderr, "Failed to export public key: %s\n", buf);
            CFRelease(errMsg);
            CFRelease(error);
        } else {
            fprintf(stderr, "Failed to export public key (unknown error)\n");
        }
        CFRelease(pubKey);
        CFRelease(privKey);
        return 1;
    }

    const UInt8 *bytes = CFDataGetBytePtr(pubData);
    size_t len = (size_t)CFDataGetLength(pubData);
    FILE *f = fopen("pub_key", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    size_t written = fwrite(bytes, 1, len, f);
    if (written != len) {
        fprintf(stderr, "Failed to write all bytes to file\n");
    }

    fclose(f);
    CFRelease(pubData);
    CFRelease(pubKey);
    CFRelease(privKey);

    return 0;
}
