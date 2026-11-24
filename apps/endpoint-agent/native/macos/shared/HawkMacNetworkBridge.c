#include "HawkMacNetworkBridge.h"

#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "../../shared/HawkBoundedSHA256.h"
#include "HawkMacPolicyBridge.h"
#include "HawkMacCodeIdentity.h"

#define HAWK_MAC_MAX_DESTINATION_HOST_BYTES 255U

static bool HawkNormalizeDestinationHost(
    const uint8_t *input,
    size_t inputLength,
    uint8_t output[HAWK_MAC_MAX_DESTINATION_HOST_BYTES],
    size_t *outputLength
) {
    if (input == NULL || output == NULL || outputLength == NULL ||
        inputLength == 0 || inputLength > HAWK_MAC_MAX_DESTINATION_HOST_BYTES) {
        return false;
    }
    size_t start = 0;
    size_t end = inputLength;
    if (end >= 2 && input[0] == '[' && input[end - 1] == ']') {
        start = 1;
        --end;
    }
    if (end > start && input[end - 1] == '.') {
        --end;
    }
    if (end <= start) return false;

    size_t written = 0;
    for (size_t index = start; index < end; ++index) {
        uint8_t observed = input[index];
        if (observed >= 'A' && observed <= 'Z') {
            observed = (uint8_t)(observed + ('a' - 'A'));
        }
        const bool accepted =
            (observed >= 'a' && observed <= 'z') ||
            (observed >= '0' && observed <= '9') ||
            observed == '.' || observed == '-' || observed == ':' ||
            observed == '%';
        if (!accepted || written >= HAWK_MAC_MAX_DESTINATION_HOST_BYTES) {
            memset(output, 0, HAWK_MAC_MAX_DESTINATION_HOST_BYTES);
            return false;
        }
        output[written++] = observed;
    }
    if (written == 0) return false;
    *outputLength = written;
    return true;
}

static bool HawkBytesEqualLiteral(
    const uint8_t *value,
    size_t valueLength,
    const char *literal
) {
    const size_t literalLength = strlen(literal);
    return valueLength == literalLength &&
        memcmp(value, literal, literalLength) == 0;
}

static bool HawkBytesStartWithLiteral(
    const uint8_t *value,
    size_t valueLength,
    const char *literal
) {
    const size_t literalLength = strlen(literal);
    return valueLength >= literalLength &&
        memcmp(value, literal, literalLength) == 0;
}

static bool HawkDestinationIsLocalhost(const uint8_t *host, size_t hostLength) {
    return HawkBytesEqualLiteral(host, hostLength, "localhost") ||
        HawkBytesEqualLiteral(host, hostLength, "::1") ||
        HawkBytesEqualLiteral(host, hostLength, "[::1]") ||
        HawkBytesStartWithLiteral(host, hostLength, "127.");
}

static uint64_t HawkMonotonicNanoseconds(void) {
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        return 0;
    }
    const __uint128_t scaled = (__uint128_t)mach_absolute_time() * timebase.numer;
    return (uint64_t)(scaled / timebase.denom);
}

static bool HawkHashAuditToken(
    const uint8_t *tokenBytes,
    size_t tokenLength,
    const char *domain,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (tokenBytes == NULL || tokenLength != sizeof(audit_token_t)) {
        return false;
    }
    audit_token_t token;
    memcpy(&token, tokenBytes, sizeof(token));
    const int pidVersion = audit_token_to_pidversion(token);
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    const bool accepted =
        HawkSHA256Update(&context, domain, strlen(domain) + 1) &&
        HawkSHA256Update(&context, &token, sizeof(token)) &&
        HawkSHA256Update(&context, &pidVersion, sizeof(pidVersion));
    memset(&token, 0, sizeof(token));
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashDestination(
    const uint8_t *host,
    size_t hostLength,
    uint16_t port,
    int32_t protocol,
    int32_t family,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (host == NULL || hostLength == 0 ||
        hostLength > HAWK_MAC_MAX_DESTINATION_HOST_BYTES || port == 0) {
        return false;
    }
    const uint64_t boundedHostLength = hostLength;
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.network-destination.v1";
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &boundedHostLength, sizeof(boundedHostLength)) &&
        HawkSHA256Update(&context, host, hostLength) &&
        HawkSHA256Update(&context, &port, sizeof(port)) &&
        HawkSHA256Update(&context, &protocol, sizeof(protocol)) &&
        HawkSHA256Update(&context, &family, sizeof(family));
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static HawkFloorPrimitive HawkNetworkPrimitive(
    const uint8_t *host,
    size_t hostLength,
    uint16_t port,
    int32_t protocol
) {
    if (HawkDestinationIsLocalhost(host, hostLength)) {
        return HAWK_FLOOR_NETWORK_LOCALHOST;
    }
    if (protocol == IPPROTO_UDP && port == 443) {
        return HAWK_FLOOR_NETWORK_QUIC;
    }
    return HAWK_FLOOR_NETWORK_CONNECT;
}

static bool HawkHashCanonicalNetworkAction(HawkFloorRequest *request) {
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.endpoint-floor.network-action.v1";
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &request->primitive, sizeof(request->primitive)) &&
        HawkSHA256Update(
            &context,
            request->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(
            &context,
            request->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(&context, &request->requestedRights, sizeof(request->requestedRights)) &&
        HawkSHA256Update(&context, &request->policyEpoch, sizeof(request->policyEpoch));
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, request->canonicalActionHash);
    return true;
}

int32_t HawkEvaluateNetworkFlow(
    const uint8_t *sourceProcessAuditToken,
    size_t sourceProcessAuditTokenLength,
    const uint8_t *sourceApplicationAuditToken,
    size_t sourceApplicationAuditTokenLength,
    const uint8_t *destinationHost,
    size_t destinationHostLength,
    uint16_t destinationPort,
    int32_t socketProtocol,
    int32_t socketFamily
) {
    HawkFloorRequest request;
    uint8_t normalizedHost[HAWK_MAC_MAX_DESTINATION_HOST_BYTES];
    size_t normalizedHostLength = 0;
    memset(&request, 0, sizeof(request));
    memset(normalizedHost, 0, sizeof(normalizedHost));
    /* A missing or unresolved signed application has no deny authority. */
    if (!HawkMacCodeIdentityFromAuditToken(sourceApplicationAuditToken,
            sourceApplicationAuditTokenLength, request.binaryIdentityHash) ||
        !HawkMacIsBinaryIdentityGoverned(request.binaryIdentityHash)) {
        return HAWK_MAC_NETWORK_VERDICT_ALLOW;
    }
    const bool enforce = HawkMacCurrentEnforcementMode() == HAWK_MAC_ENFORCEMENT_ENFORCE;
    if (!HawkNormalizeDestinationHost(
            destinationHost,
            destinationHostLength,
            normalizedHost,
            &normalizedHostLength
        )) {
        return enforce ? HAWK_MAC_NETWORK_VERDICT_BLOCK : HAWK_MAC_NETWORK_VERDICT_ALLOW;
    }
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HawkNetworkPrimitive(
        normalizedHost,
        normalizedHostLength,
        destinationPort,
        socketProtocol
    );
    request.requestedRights = 1;
    if (!HawkMacCopyPolicyBinding(
            request.tenantHash,
            request.deviceHash,
            &request.policyEpoch
        ) ||
        !HawkHashAuditToken(
            sourceProcessAuditToken,
            sourceProcessAuditTokenLength,
            "hawk.macos.network-process-instance.v1",
            request.processInstanceHash
        ) ||
        !HawkHashDestination(
            normalizedHost,
            normalizedHostLength,
            destinationPort,
            socketProtocol,
            socketFamily,
            request.destinationReferenceHash
        )) {
        memset(normalizedHost, 0, sizeof(normalizedHost));
        return enforce ? HAWK_MAC_NETWORK_VERDICT_BLOCK : HAWK_MAC_NETWORK_VERDICT_ALLOW;
    }
    memset(normalizedHost, 0, sizeof(normalizedHost));
    memcpy(
        request.processIdentityHash,
        request.binaryIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    if (!HawkHashCanonicalNetworkAction(&request)) {
        return enforce ? HAWK_MAC_NETWORK_VERDICT_BLOCK : HAWK_MAC_NETWORK_VERDICT_ALLOW;
    }
    const uint64_t now = HawkMonotonicNanoseconds();
    if (now == 0) {
        return enforce ? HAWK_MAC_NETWORK_VERDICT_BLOCK : HAWK_MAC_NETWORK_VERDICT_ALLOW;
    }
    const HawkFloorDecision decision = HawkEvaluateCurrentFloorRequest(&request, now);
    switch (decision.action) {
        case HAWK_FLOOR_ACTION_ALLOW:
        case HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE:
            return HAWK_MAC_NETWORK_VERDICT_ALLOW;
        case HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT:
        case HAWK_FLOOR_ACTION_REQUIRE_REMOTE_DECISION:
        case HAWK_FLOOR_ACTION_REQUIRE_USER_RETRY_AFTER_APPROVAL:
            return HAWK_MAC_NETWORK_VERDICT_LOCAL_RETRY_REQUIRED;
        case HAWK_FLOOR_ACTION_BLOCK:
        default:
            return HAWK_MAC_NETWORK_VERDICT_BLOCK;
    }
}
