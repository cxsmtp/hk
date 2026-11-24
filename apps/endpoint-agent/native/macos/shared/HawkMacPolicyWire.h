#ifndef HAWK_MAC_POLICY_WIRE_H
#define HAWK_MAC_POLICY_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HAWK_MAC_POLICY_WIRE_SCHEMA_VERSION 2U
#define HAWK_MAC_POLICY_ENVELOPE_MAX_BYTES (2U * 1024U * 1024U)
#define HAWK_MAC_POLICY_SIGNATURE_MAX_BYTES 80U
#define HAWK_MAC_POLICY_PUBLIC_KEY_X963_BYTES 65U

#pragma pack(push, 1)
typedef struct HawkMacPolicyEnvelopeHeader {
    uint32_t schemaVersionLittleEndian;
    uint32_t payloadLengthLittleEndian;
    uint32_t signatureLengthLittleEndian;
    uint32_t reserved;
} HawkMacPolicyEnvelopeHeader;

typedef struct HawkMacPolicyPayloadHeader {
    uint32_t schemaVersionLittleEndian;
    uint32_t floorSchemaVersionLittleEndian;
    uint64_t deliverySequenceLittleEndian;
    uint64_t policyEpochLittleEndian;
    uint64_t issuedAtUnixSecondsLittleEndian;
    uint64_t expiresAtUnixSecondsLittleEndian;
    uint32_t ruleCountLittleEndian;
    uint32_t permitCountLittleEndian;
    uint32_t governedIdentityCountLittleEndian;
    uint32_t resourceClassificationCountLittleEndian;
    uint32_t destinationClassificationCountLittleEndian;
    uint32_t modeLittleEndian;
    uint8_t tenantHash[32];
    uint8_t deviceHash[32];
    uint32_t defaultActionByPrimitiveLittleEndian[40];
    char policyVersion[64];
} HawkMacPolicyPayloadHeader;

typedef struct HawkMacPolicyRuleWire {
    uint64_t primitiveMaskLittleEndian;
    uint32_t resourceClassificationMaskLittleEndian;
    uint32_t destinationClassificationMaskLittleEndian;
    uint32_t businessPurposeLittleEndian;
    uint32_t actionLittleEndian;
    uint8_t bindBinaryIdentity;
    uint8_t reserved[7];
    uint8_t binaryIdentityHash[32];
    char ruleReference[64];
} HawkMacPolicyRuleWire;

typedef struct HawkMacPolicyPermitWire {
    uint32_t primitiveLittleEndian;
    uint64_t requestedRightsLittleEndian;
    uint64_t policyEpochLittleEndian;
    uint64_t expiresAtUnixSecondsLittleEndian;
    uint32_t maximumUsesLittleEndian;
    uint8_t processInstanceHash[32];
    uint8_t stableResourceIdentityHash[32];
    uint8_t destinationReferenceHash[32];
    uint8_t canonicalActionHash[32];
    uint8_t permitDigest[32];
} HawkMacPolicyPermitWire;

typedef struct HawkMacGovernedIdentityWire {
    uint8_t binaryIdentityHash[32];
} HawkMacGovernedIdentityWire;

typedef struct HawkMacClassificationWire {
    uint8_t referenceHash[32];
    uint32_t classificationMaskLittleEndian;
} HawkMacClassificationWire;
#pragma pack(pop)

bool HawkMacVerifyAndInstallPolicyEnvelope(
    const uint8_t *envelope,
    size_t envelopeLength,
    const uint8_t *pinnedPublicKeyX963,
    size_t pinnedPublicKeyLength,
    bool authenticatedPeer,
    uint64_t receivedAtMonotonicNs,
    uint64_t receivedAtUnixSeconds
);

#endif
