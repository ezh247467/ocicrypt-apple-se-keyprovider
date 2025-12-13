#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

static const char *DEFAULT_TAG = "se.ocicrypt.default.tag";

int main(int argc, char **argv) {
    const char *tag = (argc > 1) ? argv[1] : DEFAULT_TAG;
    printf("Using tag: %s\n", tag);

    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));

    // Build a query to delete the private key with that tag
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(query, kSecClass, kSecClassKey);
    CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(query, kSecAttrApplicationTag, tagData);
    // CFDictionaryAddValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

    OSStatus status = SecItemDelete(query);

    if (status == errSecSuccess) {
        printf("Secure Enclave key with tag '%s' deleted successfully.\n", tag);
    } else if (status == errSecItemNotFound) {
        fprintf(stderr, "Key with tag '%s' not found.\n", tag);
    } else {
        fprintf(stderr, "Failed to delete key. OSStatus: %d\n", (int)status);
    }

    CFRelease(query);
    CFRelease(tagData);

    return 0;
}
