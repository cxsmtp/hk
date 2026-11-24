#import "HawkMacCodeIdentity.h"

#import <Security/Security.h>
#import <libkern/OSByteOrder.h>
#import <bsm/libbsm.h>
#include <string.h>
#include "../../shared/HawkBoundedSHA256.h"

bool HawkMacCodeIdentityFromComponents(
    const uint8_t *team, size_t teamLength,
    const uint8_t *signing, size_t signingLength,
    const uint8_t cdhash[20], bool platformBinary,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (team == NULL || signing == NULL || cdhash == NULL || digest == NULL ||
        teamLength == 0 || teamLength > 16384 || signingLength == 0 ||
        signingLength > 16384) return false;
    static const char domain[] = "hawk.macos.code-identity.v1";
    const uint64_t teamBytes = OSSwapHostToLittleInt64(teamLength);
    const uint64_t signingBytes = OSSwapHostToLittleInt64(signingLength);
    const uint8_t platformByte = platformBinary ? 1U : 0U;
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    if (!HawkSHA256Update(&context, domain, sizeof(domain)) ||
        !HawkSHA256Update(&context, &teamBytes, sizeof(teamBytes)) ||
        !HawkSHA256Update(&context, team, teamLength) ||
        !HawkSHA256Update(&context, &signingBytes, sizeof(signingBytes)) ||
        !HawkSHA256Update(&context, signing, signingLength) ||
        !HawkSHA256Update(&context, cdhash, 20) ||
        !HawkSHA256Update(&context, &platformByte, sizeof(platformByte))) return false;
    HawkSHA256Finalize(&context, digest);
    return true;
}

bool HawkMacCodeIdentityFromESProcess(
    const es_process_t *process,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (process == NULL) return false;
    return HawkMacCodeIdentityFromComponents(
        (const uint8_t *)process->team_id.data, process->team_id.length,
        (const uint8_t *)process->signing_id.data, process->signing_id.length,
        process->cdhash, process->is_platform_binary, digest
    );
}

bool HawkMacCodeIdentityFromAuditToken(
    const uint8_t *auditToken, size_t auditTokenLength,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (auditToken == NULL || auditTokenLength != sizeof(audit_token_t) || digest == NULL)
        return false;
    CFDataRef token = CFDataCreate(kCFAllocatorDefault, auditToken, (CFIndex)auditTokenLength);
    if (token == NULL) return false;
    const void *keys[] = {kSecGuestAttributeAudit};
    const void *values[] = {token};
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    bool accepted = false;
    if (attributes != NULL && SecCodeCopyGuestWithAttributes(NULL, attributes,
            kSecCSDefaultFlags, &code) == errSecSuccess && code != NULL &&
        SecCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess &&
        SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) == errSecSuccess && information != NULL) {
        CFStringRef team = CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier);
        CFStringRef signing = CFDictionaryGetValue(information, kSecCodeInfoIdentifier);
        CFDataRef unique = CFDictionaryGetValue(information, kSecCodeInfoUnique);
        CFNumberRef platform = CFDictionaryGetValue(information, kSecCodeInfoPlatformIdentifier);
        char teamBytes[16385];
        char signingBytes[16385];
        int platformValue = 0;
        if (team != NULL && CFGetTypeID(team) == CFStringGetTypeID() &&
            signing != NULL && CFGetTypeID(signing) == CFStringGetTypeID() &&
            unique != NULL && CFGetTypeID(unique) == CFDataGetTypeID() &&
            CFDataGetLength(unique) == 20 &&
            CFStringGetCString(team, teamBytes, sizeof(teamBytes), kCFStringEncodingUTF8) &&
            CFStringGetCString(signing, signingBytes, sizeof(signingBytes), kCFStringEncodingUTF8)) {
            if (platform != NULL && CFGetTypeID(platform) == CFNumberGetTypeID())
                CFNumberGetValue(platform, kCFNumberIntType, &platformValue);
            accepted = HawkMacCodeIdentityFromComponents(
                (const uint8_t *)teamBytes, strlen(teamBytes),
                (const uint8_t *)signingBytes, strlen(signingBytes),
                CFDataGetBytePtr(unique), platformValue != 0, digest);
        }
    }
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code);
    if (attributes != NULL) CFRelease(attributes);
    CFRelease(token);
    return accepted;
}
