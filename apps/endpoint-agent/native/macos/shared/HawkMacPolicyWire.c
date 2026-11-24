#include "HawkMacPolicyWire.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libkern/OSByteOrder.h>
#include <stdlib.h>
#include <string.h>

#include "../../shared/HawkBoundedSHA256.h"
#include "HawkMacPolicyBridge.h"

_Static_assert(sizeof(HawkMacPolicyEnvelopeHeader) == 16, "wire envelope ABI changed");
_Static_assert(sizeof(HawkMacPolicyPayloadHeader) == 352, "wire payload ABI changed");

static bool HawkCheckedAdd(size_t left, size_t right, size_t *result) {
    if (result == NULL || right > SIZE_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

static bool HawkCheckedMultiply(size_t left, size_t right, size_t *result) {
    if (result == NULL || (left != 0 && right > SIZE_MAX / left)) {
        return false;
    }
    *result = left * right;
    return true;
}

static bool HawkVerifyPolicySignature(
    const uint8_t *payload,
    size_t payloadLength,
    const uint8_t *signature,
    size_t signatureLength,
    const uint8_t *publicKey,
    size_t publicKeyLength
) {
    if (payload == NULL || payloadLength == 0 || signature == NULL ||
        signatureLength < 8 || signatureLength > HAWK_MAC_POLICY_SIGNATURE_MAX_BYTES ||
        publicKey == NULL ||
        publicKeyLength != HAWK_MAC_POLICY_PUBLIC_KEY_X963_BYTES ||
        publicKey[0] != 0x04U) {
        return false;
    }
    CFDataRef publicKeyData = CFDataCreate(
        kCFAllocatorDefault,
        publicKey,
        (CFIndex)publicKeyLength
    );
    CFNumberRef keySize = NULL;
    CFDictionaryRef attributes = NULL;
    SecKeyRef key = NULL;
    CFDataRef payloadData = NULL;
    CFDataRef signatureData = NULL;
    CFErrorRef error = NULL;
    bool verified = false;
    const int keyBits = 256;
    if (publicKeyData == NULL) {
        goto cleanup;
    }
    keySize = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keyBits);
    if (keySize == NULL) {
        goto cleanup;
    }
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
    const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, keySize};
    attributes = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (attributes == NULL) {
        goto cleanup;
    }
    key = SecKeyCreateWithData(publicKeyData, attributes, &error);
    if (key == NULL) {
        goto cleanup;
    }
    payloadData = CFDataCreate(kCFAllocatorDefault, payload, (CFIndex)payloadLength);
    signatureData = CFDataCreate(
        kCFAllocatorDefault,
        signature,
        (CFIndex)signatureLength
    );
    if (payloadData == NULL || signatureData == NULL) {
        goto cleanup;
    }
    verified = SecKeyVerifySignature(
        key,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        payloadData,
        signatureData,
        &error
    );

cleanup:
    if (error != NULL) {
        CFRelease(error);
    }
    if (signatureData != NULL) {
        CFRelease(signatureData);
    }
    if (payloadData != NULL) {
        CFRelease(payloadData);
    }
    if (key != NULL) {
        CFRelease(key);
    }
    if (attributes != NULL) {
        CFRelease(attributes);
    }
    if (keySize != NULL) {
        CFRelease(keySize);
    }
    if (publicKeyData != NULL) {
        CFRelease(publicKeyData);
    }
    return verified;
}

static bool HawkExpectedPayloadLength(
    uint32_t ruleCount, uint32_t permitCount, uint32_t identityCount,
    uint32_t resourceCount, uint32_t destinationCount, size_t *expectedLength
) {
    size_t rulesLength = 0;
    size_t permitsLength = 0;
    size_t identitiesLength = 0;
    size_t resourcesLength = 0;
    size_t destinationsLength = 0;
    size_t total = sizeof(HawkMacPolicyPayloadHeader);
    return ruleCount <= HAWK_FLOOR_MAX_RULES &&
        permitCount <= HAWK_FLOOR_MAX_PERMITS &&
        identityCount <= HAWK_MAC_MAX_GOVERNED_IDENTITIES &&
        resourceCount <= HAWK_MAC_MAX_CLASSIFICATIONS &&
        destinationCount <= HAWK_MAC_MAX_CLASSIFICATIONS &&
        HawkCheckedMultiply(ruleCount, sizeof(HawkMacPolicyRuleWire), &rulesLength) &&
        HawkCheckedMultiply(permitCount, sizeof(HawkMacPolicyPermitWire), &permitsLength) &&
        HawkCheckedMultiply(identityCount, sizeof(HawkMacGovernedIdentityWire), &identitiesLength) &&
        HawkCheckedMultiply(resourceCount, sizeof(HawkMacClassificationWire), &resourcesLength) &&
        HawkCheckedMultiply(destinationCount, sizeof(HawkMacClassificationWire), &destinationsLength) &&
        HawkCheckedAdd(total, rulesLength, &total) &&
        HawkCheckedAdd(total, permitsLength, &total) &&
        HawkCheckedAdd(total, identitiesLength, &total) &&
        HawkCheckedAdd(total, resourcesLength, &total) &&
        HawkCheckedAdd(total, destinationsLength, &total) &&
        ((*expectedLength = total), true);
}

static bool HawkDecodeRules(
    const HawkMacPolicyRuleWire *wire,
    uint32_t count,
    HawkFloorRule *rules
) {
    for (uint32_t index = 0; index < count; ++index) {
        const HawkMacPolicyRuleWire *source = &wire[index];
        HawkFloorRule *target = &rules[index];
        if (source->bindBinaryIdentity > 1) {
            return false;
        }
        memset(target, 0, sizeof(*target));
        target->primitiveMask = OSSwapLittleToHostInt64(
            source->primitiveMaskLittleEndian
        );
        target->resourceClassificationMask = OSSwapLittleToHostInt32(
            source->resourceClassificationMaskLittleEndian
        );
        target->destinationClassificationMask = OSSwapLittleToHostInt32(
            source->destinationClassificationMaskLittleEndian
        );
        target->businessPurpose = OSSwapLittleToHostInt32(
            source->businessPurposeLittleEndian
        );
        target->action = (HawkFloorAction)OSSwapLittleToHostInt32(
            source->actionLittleEndian
        );
        target->bindBinaryIdentity = source->bindBinaryIdentity == 1;
        memcpy(target->binaryIdentityHash, source->binaryIdentityHash, 32);
        memcpy(target->ruleReference, source->ruleReference, 64);
    }
    return true;
}

static bool HawkDecodePermits(
    const HawkMacPolicyPermitWire *wire,
    uint32_t count,
    HawkFloorPermit *permits,
    uint64_t policyExpiryUnix,
    uint64_t nowUnix,
    uint64_t receivedMonotonic
) {
    for (uint32_t index = 0; index < count; ++index) {
        const HawkMacPolicyPermitWire *source = &wire[index];
        HawkFloorPermit *target = &permits[index];
        memset(target, 0, sizeof(*target));
        target->integrityVerified = true;
        target->primitive = (HawkFloorPrimitive)OSSwapLittleToHostInt32(
            source->primitiveLittleEndian
        );
        target->requestedRights = OSSwapLittleToHostInt64(
            source->requestedRightsLittleEndian
        );
        target->policyEpoch = OSSwapLittleToHostInt64(source->policyEpochLittleEndian);
        const uint64_t expiry = OSSwapLittleToHostInt64(source->expiresAtUnixSecondsLittleEndian);
        if (expiry <= nowUnix || expiry > policyExpiryUnix ||
            expiry - nowUnix > UINT64_MAX / 1000000000ULL ||
            receivedMonotonic > UINT64_MAX - (expiry - nowUnix) * 1000000000ULL) {
            return false;
        }
        target->expiresAtMonotonicNs = receivedMonotonic + (expiry - nowUnix) * 1000000000ULL;
        target->maximumUses = OSSwapLittleToHostInt32(source->maximumUsesLittleEndian);
        memcpy(target->processInstanceHash, source->processInstanceHash, 32);
        memcpy(target->stableResourceIdentityHash, source->stableResourceIdentityHash, 32);
        memcpy(target->destinationReferenceHash, source->destinationReferenceHash, 32);
        memcpy(target->canonicalActionHash, source->canonicalActionHash, 32);
        memcpy(target->permitDigest, source->permitDigest, 32);
    }
    return true;
}

bool HawkMacVerifyAndInstallPolicyEnvelope(
    const uint8_t *envelope,
    size_t envelopeLength,
    const uint8_t *pinnedPublicKeyX963,
    size_t pinnedPublicKeyLength,
    bool authenticatedPeer,
    uint64_t receivedAtMonotonicNs,
    uint64_t receivedAtUnixSeconds
) {
    if (!authenticatedPeer || envelope == NULL ||
        envelopeLength < sizeof(HawkMacPolicyEnvelopeHeader) ||
        envelopeLength > HAWK_MAC_POLICY_ENVELOPE_MAX_BYTES ||
        receivedAtMonotonicNs == 0 || receivedAtUnixSeconds == 0) {
        return false;
    }
    const HawkMacPolicyEnvelopeHeader *envelopeHeader =
        (const HawkMacPolicyEnvelopeHeader *)envelope;
    const uint32_t envelopeSchema = OSSwapLittleToHostInt32(
        envelopeHeader->schemaVersionLittleEndian
    );
    const uint32_t payloadLength = OSSwapLittleToHostInt32(
        envelopeHeader->payloadLengthLittleEndian
    );
    const uint32_t signatureLength = OSSwapLittleToHostInt32(
        envelopeHeader->signatureLengthLittleEndian
    );
    size_t expectedEnvelopeLength = sizeof(HawkMacPolicyEnvelopeHeader);
    if (envelopeSchema != HAWK_MAC_POLICY_WIRE_SCHEMA_VERSION ||
        envelopeHeader->reserved != 0 || payloadLength < sizeof(HawkMacPolicyPayloadHeader) ||
        signatureLength < 8 || signatureLength > HAWK_MAC_POLICY_SIGNATURE_MAX_BYTES ||
        !HawkCheckedAdd(expectedEnvelopeLength, payloadLength, &expectedEnvelopeLength) ||
        !HawkCheckedAdd(expectedEnvelopeLength, signatureLength, &expectedEnvelopeLength) ||
        expectedEnvelopeLength != envelopeLength) {
        return false;
    }
    const uint8_t *payload = envelope + sizeof(HawkMacPolicyEnvelopeHeader);
    const uint8_t *signature = payload + payloadLength;
    if (!HawkVerifyPolicySignature(
            payload,
            payloadLength,
            signature,
            signatureLength,
            pinnedPublicKeyX963,
            pinnedPublicKeyLength
        )) {
        return false;
    }

    const HawkMacPolicyPayloadHeader *header =
        (const HawkMacPolicyPayloadHeader *)payload;
    const uint32_t payloadSchema = OSSwapLittleToHostInt32(
        header->schemaVersionLittleEndian
    );
    const uint32_t floorSchema = OSSwapLittleToHostInt32(
        header->floorSchemaVersionLittleEndian
    );
    const uint32_t ruleCount = OSSwapLittleToHostInt32(header->ruleCountLittleEndian);
    const uint32_t permitCount = OSSwapLittleToHostInt32(
        header->permitCountLittleEndian
    );
    const uint32_t identityCount = OSSwapLittleToHostInt32(header->governedIdentityCountLittleEndian);
    const uint32_t resourceCount = OSSwapLittleToHostInt32(header->resourceClassificationCountLittleEndian);
    const uint32_t destinationCount = OSSwapLittleToHostInt32(header->destinationClassificationCountLittleEndian);
    const uint64_t issuedAt = OSSwapLittleToHostInt64(header->issuedAtUnixSecondsLittleEndian);
    const uint64_t expiresAt = OSSwapLittleToHostInt64(header->expiresAtUnixSecondsLittleEndian);
    const uint64_t maxLifetime = 24ULL * 60ULL * 60ULL;
    if (receivedAtUnixSeconds > UINT64_MAX - 60ULL ||
        issuedAt > receivedAtUnixSeconds + 60ULL || expiresAt <= receivedAtUnixSeconds ||
        expiresAt <= issuedAt || expiresAt - issuedAt > maxLifetime ||
        expiresAt - receivedAtUnixSeconds > UINT64_MAX / 1000000000ULL ||
        receivedAtMonotonicNs > UINT64_MAX -
            (expiresAt - receivedAtUnixSeconds) * 1000000000ULL) {
        return false;
    }
    size_t expectedPayloadLength = 0;
    if (payloadSchema != HAWK_MAC_POLICY_WIRE_SCHEMA_VERSION ||
        floorSchema != HAWK_FLOOR_SCHEMA_VERSION ||
        !HawkExpectedPayloadLength(ruleCount, permitCount, identityCount, resourceCount,
            destinationCount, &expectedPayloadLength) ||
        expectedPayloadLength != payloadLength) {
        return false;
    }

    HawkFloorRule *rules = ruleCount == 0
        ? NULL
        : (HawkFloorRule *)calloc(ruleCount, sizeof(HawkFloorRule));
    HawkFloorPermit *permits = permitCount == 0
        ? NULL
        : (HawkFloorPermit *)calloc(permitCount, sizeof(HawkFloorPermit));
    if ((ruleCount > 0 && rules == NULL) || (permitCount > 0 && permits == NULL)) {
        free(rules);
        free(permits);
        return false;
    }
    const uint8_t *cursor = payload + sizeof(HawkMacPolicyPayloadHeader);
    const HawkMacPolicyRuleWire *wireRules = (const HawkMacPolicyRuleWire *)cursor;
    cursor += sizeof(HawkMacPolicyRuleWire) * ruleCount;
    const HawkMacPolicyPermitWire *wirePermits = (const HawkMacPolicyPermitWire *)cursor;
    bool decoded = HawkDecodeRules(wireRules, ruleCount, rules);
    if (decoded) {
        decoded = HawkDecodePermits(wirePermits, permitCount, permits, expiresAt,
            receivedAtUnixSeconds, receivedAtMonotonicNs);
    }
    cursor += sizeof(HawkMacPolicyPermitWire) * permitCount;
    const HawkMacGovernedIdentityWire *wireIdentities = (const HawkMacGovernedIdentityWire *)cursor;
    cursor += sizeof(HawkMacGovernedIdentityWire) * identityCount;
    const HawkMacClassificationWire *wireResources = (const HawkMacClassificationWire *)cursor;
    cursor += sizeof(HawkMacClassificationWire) * resourceCount;
    const HawkMacClassificationWire *wireDestinations = (const HawkMacClassificationWire *)cursor;

    HawkFloorPolicySnapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.schemaVersion = floorSchema;
    snapshot.signatureVerified = true;
    snapshot.configurationIntegrityValid = true;
    snapshot.policyEpoch = OSSwapLittleToHostInt64(header->policyEpochLittleEndian);
    snapshot.expiresAtMonotonicNs = receivedAtMonotonicNs +
        (expiresAt - receivedAtUnixSeconds) * 1000000000ULL;
    snapshot.ruleCount = ruleCount;
    snapshot.rules = rules;
    snapshot.permitCount = permitCount;
    snapshot.permits = permits;
    memcpy(snapshot.tenantHash, header->tenantHash, 32);
    memcpy(snapshot.deviceHash, header->deviceHash, 32);
    memcpy(snapshot.policyVersion, header->policyVersion, 64);
    for (uint32_t index = 0; index < HAWK_FLOOR_PRIMITIVE_COUNT; ++index) {
        snapshot.defaultActionByPrimitive[index] =
            (HawkFloorAction)OSSwapLittleToHostInt32(
                header->defaultActionByPrimitiveLittleEndian[index]
            );
    }

    HawkMacPolicyAdmission admission;
    memset(&admission, 0, sizeof(admission));
    admission.schemaVersion = HAWK_MAC_POLICY_ADMISSION_SCHEMA_VERSION;
    admission.authenticatedPeer = true;
    admission.signatureVerified = true;
    admission.signerPinVerified = true;
    admission.configurationIntegrityValid = true;
    admission.deliverySequence = OSSwapLittleToHostInt64(
        header->deliverySequenceLittleEndian
    );
    admission.receivedAtMonotonicNs = receivedAtMonotonicNs;
    admission.receivedAtUnixSeconds = receivedAtUnixSeconds;
    admission.issuedAtUnixSeconds = issuedAt;
    admission.expiresAtUnixSeconds = expiresAt;
    admission.mode = (HawkMacEnforcementMode)OSSwapLittleToHostInt32(header->modeLittleEndian);
    admission.governedIdentityCount = identityCount;
    for (uint32_t index = 0; index < identityCount; ++index) {
        memcpy(admission.governedIdentities[index], wireIdentities[index].binaryIdentityHash, HAWK_FLOOR_HASH_BYTES);
    }
    admission.resourceClassificationCount = resourceCount;
    for (uint32_t index = 0; index < resourceCount; ++index) {
        memcpy(admission.resourceReferences[index], wireResources[index].referenceHash, HAWK_FLOOR_HASH_BYTES);
        admission.resourceMasks[index] = OSSwapLittleToHostInt32(wireResources[index].classificationMaskLittleEndian);
    }
    admission.destinationClassificationCount = destinationCount;
    for (uint32_t index = 0; index < destinationCount; ++index) {
        memcpy(admission.destinationReferences[index], wireDestinations[index].referenceHash, HAWK_FLOOR_HASH_BYTES);
        admission.destinationMasks[index] = OSSwapLittleToHostInt32(wireDestinations[index].classificationMaskLittleEndian);
    }
    HawkSHA256Context digestContext;
    HawkSHA256Initialize(&digestContext);
    decoded = decoded && HawkSHA256Update(&digestContext, payload, payloadLength);
    if (decoded) {
        HawkSHA256Finalize(&digestContext, admission.bundleDigest);
    }
    const bool installed = decoded && HawkMacInstallPolicySnapshot(&snapshot, &admission);
    if (rules != NULL) {
        memset(rules, 0, sizeof(HawkFloorRule) * ruleCount);
    }
    if (permits != NULL) {
        memset(permits, 0, sizeof(HawkFloorPermit) * permitCount);
    }
    free(rules);
    free(permits);
    return installed;
}
