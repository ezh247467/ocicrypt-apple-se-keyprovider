#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

int main(void) {
    const char *tag = "se.ocicrypt.default.tag";

    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));

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
