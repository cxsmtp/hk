#ifndef HAWK_MAC_POLICY_BRIDGE_H
#define HAWK_MAC_POLICY_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

#include "../../shared/HawkFloorDecisionEngine.h"

#define HAWK_MAC_POLICY_ADMISSION_SCHEMA_VERSION 1U
#define HAWK_MAC_POLICY_HEALTH_SCHEMA_VERSION 1U
#define HAWK_MAC_MAX_GOVERNED_IDENTITIES 256U
#define HAWK_MAC_MAX_CLASSIFICATIONS 1024U
#define HAWK_MAC_KNOWN_RESOURCE_CLASSIFICATIONS 0x0000FFFFU
#define HAWK_MAC_KNOWN_DESTINATION_CLASSIFICATIONS 0x0000FFFFU

typedef enum HawkMacEnforcementMode {
    HAWK_MAC_ENFORCEMENT_DISARMED = 0,
    HAWK_MAC_ENFORCEMENT_MONITOR = 1,
    HAWK_MAC_ENFORCEMENT_ENFORCE = 2
} HawkMacEnforcementMode;

typedef enum HawkMacPolicyRejectionReason {
    HAWK_MAC_POLICY_REJECTION_NONE = 0,
    HAWK_MAC_POLICY_REJECTION_INVALID_ARGUMENT = 1,
    HAWK_MAC_POLICY_REJECTION_UNAUTHENTICATED_PEER = 2,
    HAWK_MAC_POLICY_REJECTION_SIGNATURE_UNVERIFIED = 3,
    HAWK_MAC_POLICY_REJECTION_SIGNER_PIN_UNVERIFIED = 4,
    HAWK_MAC_POLICY_REJECTION_CONFIGURATION_INTEGRITY = 5,
    HAWK_MAC_POLICY_REJECTION_SCHEMA = 6,
    HAWK_MAC_POLICY_REJECTION_OVERSIZED = 7,
    HAWK_MAC_POLICY_REJECTION_SEQUENCE_ROLLBACK = 8,
    HAWK_MAC_POLICY_REJECTION_EPOCH_ROLLBACK = 9,
    HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL = 10
    ,HAWK_MAC_POLICY_REJECTION_TIME_BOUNDS = 11
    ,HAWK_MAC_POLICY_REJECTION_UNSCOPED_RULE = 12
    ,HAWK_MAC_POLICY_REJECTION_CLASSIFICATION = 13
} HawkMacPolicyRejectionReason;

/*
 * Admission is created only after the containing signed System Extension has
 * authenticated its XPC peer, pinned the peer's code-signing requirement, and
 * verified the detached policy signature. The authorization callback never
 * performs those expensive operations or a remote lookup.
 */
typedef struct HawkMacPolicyAdmission {
    uint32_t schemaVersion;
    bool authenticatedPeer;
    bool signatureVerified;
    bool signerPinVerified;
    bool configurationIntegrityValid;
    uint64_t deliverySequence;
    uint64_t receivedAtMonotonicNs;
    uint64_t receivedAtUnixSeconds;
    uint64_t issuedAtUnixSeconds;
    uint64_t expiresAtUnixSeconds;
    HawkMacEnforcementMode mode;
    uint32_t governedIdentityCount;
    uint8_t governedIdentities[HAWK_MAC_MAX_GOVERNED_IDENTITIES][HAWK_FLOOR_HASH_BYTES];
    uint32_t resourceClassificationCount;
    uint8_t resourceReferences[HAWK_MAC_MAX_CLASSIFICATIONS][HAWK_FLOOR_HASH_BYTES];
    uint32_t resourceMasks[HAWK_MAC_MAX_CLASSIFICATIONS];
    uint32_t destinationClassificationCount;
    uint8_t destinationReferences[HAWK_MAC_MAX_CLASSIFICATIONS][HAWK_FLOOR_HASH_BYTES];
    uint32_t destinationMasks[HAWK_MAC_MAX_CLASSIFICATIONS];
    uint8_t bundleDigest[HAWK_FLOOR_HASH_BYTES];
} HawkMacPolicyAdmission;

typedef struct HawkMacPolicyHealth {
    uint32_t schemaVersion;
    bool active;
    bool authenticatedPeer;
    bool signatureVerified;
    bool signerPinVerified;
    bool configurationIntegrityValid;
    uint64_t policyEpoch;
    uint64_t deliverySequence;
    uint64_t expiresAtMonotonicNs;
    uint64_t issuedAtUnixSeconds;
    uint64_t expiresAtUnixSeconds;
    HawkMacEnforcementMode mode;
    bool policyCurrent;
    uint64_t wouldBlockCount;
    uint64_t ungovernedAllowCount;
    uint64_t acceptedDeliveryCount;
    uint64_t rejectedDeliveryCount;
    HawkMacPolicyRejectionReason lastRejectionReason;
    uint8_t bundleDigest[HAWK_FLOOR_HASH_BYTES];
    char policyVersion[HAWK_FLOOR_REFERENCE_BYTES];
} HawkMacPolicyHealth;

typedef void (*HawkMacPolicyEpochObserver)(
    uint64_t previousPolicyEpoch,
    uint64_t currentPolicyEpoch,
    void *context
);

bool HawkMacInstallPolicySnapshot(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkMacPolicyAdmission *admission
);

HawkFloorDecision HawkEvaluateCurrentFloorRequest(
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
);

bool HawkMacIsBinaryIdentityGoverned(
    const uint8_t binaryIdentityHash[HAWK_FLOOR_HASH_BYTES]
);

HawkMacEnforcementMode HawkMacCurrentEnforcementMode(void);

bool HawkMacCopyPolicyBinding(
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES],
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES],
    uint64_t *policyEpoch
);

bool HawkMacCopyPolicyHealth(HawkMacPolicyHealth *health);

void HawkMacSetPolicyEpochObserver(
    HawkMacPolicyEpochObserver observer,
    void *context
);

/* Diagnostic-only borrowed view. Authorization callbacks use the locked
 * HawkEvaluateCurrentFloorRequest entry point instead. */
const HawkFloorPolicySnapshot *HawkCurrentSignedPolicySnapshot(void);

#if defined(HAWK_MAC_POLICY_TESTING)
void HawkMacClearPolicySnapshotForTesting(void);
#endif

#endif
