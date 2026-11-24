#include "HawkMacPolicyBridge.h"

#include <os/lock.h>
#include <mach/mach_time.h>
#include <string.h>
#include <time.h>

typedef struct HawkMacPolicySlot {
    HawkFloorPolicySnapshot snapshot;
    HawkFloorRule rules[HAWK_FLOOR_MAX_RULES];
    HawkFloorPermit permits[HAWK_FLOOR_MAX_PERMITS];
    uint8_t governedIdentities[HAWK_MAC_MAX_GOVERNED_IDENTITIES][HAWK_FLOOR_HASH_BYTES];
    uint8_t resourceReferences[HAWK_MAC_MAX_CLASSIFICATIONS][HAWK_FLOOR_HASH_BYTES];
    uint32_t resourceMasks[HAWK_MAC_MAX_CLASSIFICATIONS];
    uint8_t destinationReferences[HAWK_MAC_MAX_CLASSIFICATIONS][HAWK_FLOOR_HASH_BYTES];
    uint32_t destinationMasks[HAWK_MAC_MAX_CLASSIFICATIONS];
    uint32_t governedIdentityCount;
    uint32_t resourceClassificationCount;
    uint32_t destinationClassificationCount;
    HawkMacEnforcementMode mode;
    uint64_t issuedAtUnixSeconds;
    uint64_t expiresAtUnixSeconds;
} HawkMacPolicySlot;

static os_unfair_lock sPolicyLock = OS_UNFAIR_LOCK_INIT;
static HawkMacPolicySlot sPolicySlots[2];
static uint32_t sActiveSlot = 0;
static bool sHasActivePolicy = false;
static HawkMacPolicyEpochObserver sPolicyEpochObserver = NULL;
static void *sPolicyEpochObserverContext = NULL;
static HawkMacPolicyHealth sHealth = {
    .schemaVersion = HAWK_MAC_POLICY_HEALTH_SCHEMA_VERSION,
};

static bool HawkBytesAllZero(const uint8_t *value, size_t count) {
    uint8_t combined = 0;
    for (size_t index = 0; index < count; ++index) {
        combined |= value[index];
    }
    return combined == 0;
}

static bool HawkBytesEqual(
    const uint8_t *left,
    const uint8_t *right,
    size_t count
) {
    uint8_t difference = 0;
    for (size_t index = 0; index < count; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static bool HawkActionValid(HawkFloorAction action) {
    return action >= HAWK_FLOOR_ACTION_ALLOW &&
        action <= HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE;
}

static bool HawkPrimitiveValid(HawkFloorPrimitive primitive) {
    return primitive >= HAWK_FLOOR_FILE_OPEN &&
        primitive < HAWK_FLOOR_PRIMITIVE_COUNT;
}

static bool HawkReferenceTerminated(const char value[HAWK_FLOOR_REFERENCE_BYTES]) {
    return memchr(value, '\0', HAWK_FLOOR_REFERENCE_BYTES) != NULL;
}

static bool HawkIdentityInAdmission(
    const HawkMacPolicyAdmission *admission,
    const uint8_t identity[HAWK_FLOOR_HASH_BYTES]
) {
    if (HawkBytesAllZero(identity, HAWK_FLOOR_HASH_BYTES)) return false;
    for (uint32_t index = 0; index < admission->governedIdentityCount; ++index) {
        if (HawkBytesEqual(admission->governedIdentities[index], identity, HAWK_FLOOR_HASH_BYTES))
            return true;
    }
    return false;
}

static bool HawkRulesValid(const HawkFloorPolicySnapshot *snapshot,
                           const HawkMacPolicyAdmission *admission) {
    const uint64_t validMask = HAWK_FLOOR_PRIMITIVE_COUNT == 64
        ? UINT64_MAX
        : ((1ULL << HAWK_FLOOR_PRIMITIVE_COUNT) - 1ULL);
    for (uint32_t index = 0; index < snapshot->ruleCount; ++index) {
        const HawkFloorRule *rule = &snapshot->rules[index];
        if (rule->primitiveMask == 0 || (rule->primitiveMask & ~validMask) != 0 ||
            !HawkActionValid(rule->action) ||
            !HawkReferenceTerminated(rule->ruleReference)) {
            return false;
        }
        if (rule->action != HAWK_FLOOR_ACTION_ALLOW &&
            rule->action != HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE &&
            (!rule->bindBinaryIdentity ||
             !HawkIdentityInAdmission(admission, rule->binaryIdentityHash))) {
            return false;
        }
    }
    return true;
}

static bool HawkPermitsValid(const HawkFloorPolicySnapshot *snapshot) {
    for (uint32_t index = 0; index < snapshot->permitCount; ++index) {
        const HawkFloorPermit *permit = &snapshot->permits[index];
        if (!permit->integrityVerified || !HawkPrimitiveValid(permit->primitive) ||
            permit->policyEpoch != snapshot->policyEpoch ||
            permit->maximumUses == 0 ||
            permit->consumedUses > permit->maximumUses ||
            HawkBytesAllZero(permit->processInstanceHash, HAWK_FLOOR_HASH_BYTES) ||
            HawkBytesAllZero(permit->canonicalActionHash, HAWK_FLOOR_HASH_BYTES) ||
            HawkBytesAllZero(permit->permitDigest, HAWK_FLOOR_HASH_BYTES)) {
            return false;
        }
    }
    return true;
}

static HawkMacPolicyRejectionReason HawkValidateDelivery(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkMacPolicyAdmission *admission
) {
    if (snapshot == NULL || admission == NULL) {
        return HAWK_MAC_POLICY_REJECTION_INVALID_ARGUMENT;
    }
    if (admission->schemaVersion != HAWK_MAC_POLICY_ADMISSION_SCHEMA_VERSION ||
        snapshot->schemaVersion != HAWK_FLOOR_SCHEMA_VERSION) {
        return HAWK_MAC_POLICY_REJECTION_SCHEMA;
    }
    if (!admission->authenticatedPeer) {
        return HAWK_MAC_POLICY_REJECTION_UNAUTHENTICATED_PEER;
    }
    if (!admission->signatureVerified || !snapshot->signatureVerified) {
        return HAWK_MAC_POLICY_REJECTION_SIGNATURE_UNVERIFIED;
    }
    if (!admission->signerPinVerified) {
        return HAWK_MAC_POLICY_REJECTION_SIGNER_PIN_UNVERIFIED;
    }
    if (!admission->configurationIntegrityValid ||
        !snapshot->configurationIntegrityValid) {
        return HAWK_MAC_POLICY_REJECTION_CONFIGURATION_INTEGRITY;
    }
    if (admission->mode < HAWK_MAC_ENFORCEMENT_DISARMED ||
        admission->mode > HAWK_MAC_ENFORCEMENT_ENFORCE) {
        return HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL;
    }
    if (admission->governedIdentityCount > HAWK_MAC_MAX_GOVERNED_IDENTITIES ||
        admission->resourceClassificationCount > HAWK_MAC_MAX_CLASSIFICATIONS ||
        admission->destinationClassificationCount > HAWK_MAC_MAX_CLASSIFICATIONS) {
        return HAWK_MAC_POLICY_REJECTION_OVERSIZED;
    }
    for (uint32_t index = 0; index < admission->governedIdentityCount; ++index) {
        if (HawkBytesAllZero(admission->governedIdentities[index], HAWK_FLOOR_HASH_BYTES)) {
            return HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL;
        }
    }
    for (uint32_t index = 0; index < admission->resourceClassificationCount; ++index) {
        if (HawkBytesAllZero(admission->resourceReferences[index], HAWK_FLOOR_HASH_BYTES) ||
            admission->resourceMasks[index] == 0 ||
            (admission->resourceMasks[index] & ~HAWK_MAC_KNOWN_RESOURCE_CLASSIFICATIONS) != 0) {
            return HAWK_MAC_POLICY_REJECTION_CLASSIFICATION;
        }
        for (uint32_t prior = 0; prior < index; ++prior) {
            if (HawkBytesEqual(admission->resourceReferences[prior], admission->resourceReferences[index], HAWK_FLOOR_HASH_BYTES) &&
                admission->resourceMasks[prior] != admission->resourceMasks[index]) {
                return HAWK_MAC_POLICY_REJECTION_CLASSIFICATION;
            }
        }
    }
    for (uint32_t index = 0; index < admission->destinationClassificationCount; ++index) {
        if (HawkBytesAllZero(admission->destinationReferences[index], HAWK_FLOOR_HASH_BYTES) ||
            admission->destinationMasks[index] == 0 ||
            (admission->destinationMasks[index] & ~HAWK_MAC_KNOWN_DESTINATION_CLASSIFICATIONS) != 0) {
            return HAWK_MAC_POLICY_REJECTION_CLASSIFICATION;
        }
        for (uint32_t prior = 0; prior < index; ++prior) {
            if (HawkBytesEqual(admission->destinationReferences[prior], admission->destinationReferences[index], HAWK_FLOOR_HASH_BYTES) &&
                admission->destinationMasks[prior] != admission->destinationMasks[index]) {
                return HAWK_MAC_POLICY_REJECTION_CLASSIFICATION;
            }
        }
    }
    if (snapshot->ruleCount > HAWK_FLOOR_MAX_RULES ||
        snapshot->permitCount > HAWK_FLOOR_MAX_PERMITS) {
        return HAWK_MAC_POLICY_REJECTION_OVERSIZED;
    }
    if ((snapshot->ruleCount > 0 && snapshot->rules == NULL) ||
        (snapshot->permitCount > 0 && snapshot->permits == NULL) ||
        snapshot->policyEpoch == 0 || admission->deliverySequence == 0 ||
        snapshot->expiresAtMonotonicNs <= admission->receivedAtMonotonicNs ||
        HawkBytesAllZero(snapshot->tenantHash, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(snapshot->deviceHash, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(admission->bundleDigest, HAWK_FLOOR_HASH_BYTES) ||
        !HawkReferenceTerminated(snapshot->policyVersion)) {
        return HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL;
    }
    for (uint32_t index = 0; index < HAWK_FLOOR_PRIMITIVE_COUNT; ++index) {
        if (snapshot->defaultActionByPrimitive[index] != HAWK_FLOOR_ACTION_ALLOW &&
            snapshot->defaultActionByPrimitive[index] != HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE) {
            return HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL;
        }
    }
    if (!HawkRulesValid(snapshot, admission) || !HawkPermitsValid(snapshot)) {
        return HAWK_MAC_POLICY_REJECTION_MALFORMED_MATERIAL;
    }
    return HAWK_MAC_POLICY_REJECTION_NONE;
}

static void HawkRecordRejection(HawkMacPolicyRejectionReason reason) {
    sHealth.rejectedDeliveryCount += 1;
    sHealth.lastRejectionReason = reason;
}

bool HawkMacInstallPolicySnapshot(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkMacPolicyAdmission *admission
) {
    HawkMacPolicyRejectionReason rejection = HawkValidateDelivery(snapshot, admission);
    os_unfair_lock_lock(&sPolicyLock);
    if (rejection != HAWK_MAC_POLICY_REJECTION_NONE) {
        HawkRecordRejection(rejection);
        os_unfair_lock_unlock(&sPolicyLock);
        return false;
    }
    if (sHasActivePolicy &&
        admission->deliverySequence <= sHealth.deliverySequence) {
        HawkRecordRejection(HAWK_MAC_POLICY_REJECTION_SEQUENCE_ROLLBACK);
        os_unfair_lock_unlock(&sPolicyLock);
        return false;
    }
    if (sHasActivePolicy && snapshot->policyEpoch < sHealth.policyEpoch) {
        HawkRecordRejection(HAWK_MAC_POLICY_REJECTION_EPOCH_ROLLBACK);
        os_unfair_lock_unlock(&sPolicyLock);
        return false;
    }

    const uint64_t previousPolicyEpoch = sHasActivePolicy ? sHealth.policyEpoch : 0;
    const uint32_t nextSlot = sHasActivePolicy ? (sActiveSlot ^ 1U) : 0U;
    HawkMacPolicySlot *slot = &sPolicySlots[nextSlot];
    memset(slot, 0, sizeof(*slot));
    memcpy(&slot->snapshot, snapshot, sizeof(slot->snapshot));
    if (snapshot->ruleCount > 0) {
        memcpy(slot->rules, snapshot->rules,
            sizeof(HawkFloorRule) * snapshot->ruleCount);
        slot->snapshot.rules = slot->rules;
    } else {
        slot->snapshot.rules = NULL;
    }
    /* The policy slot owns all fixed-capacity authorization material. */
    slot->mode = admission->mode;
    slot->issuedAtUnixSeconds = admission->issuedAtUnixSeconds;
    slot->expiresAtUnixSeconds = admission->expiresAtUnixSeconds;
    slot->governedIdentityCount = admission->governedIdentityCount;
    memcpy(slot->governedIdentities, admission->governedIdentities, sizeof(slot->governedIdentities));
    slot->resourceClassificationCount = admission->resourceClassificationCount;
    memcpy(slot->resourceReferences, admission->resourceReferences, sizeof(slot->resourceReferences));
    memcpy(slot->resourceMasks, admission->resourceMasks, sizeof(slot->resourceMasks));
    slot->destinationClassificationCount = admission->destinationClassificationCount;
    memcpy(slot->destinationReferences, admission->destinationReferences, sizeof(slot->destinationReferences));
    memcpy(slot->destinationMasks, admission->destinationMasks, sizeof(slot->destinationMasks));
    if (snapshot->permitCount > 0) {
        memcpy(slot->permits, snapshot->permits,
            sizeof(HawkFloorPermit) * snapshot->permitCount);
        slot->snapshot.permits = slot->permits;
    } else {
        slot->snapshot.permits = NULL;
    }

    sActiveSlot = nextSlot;
    sHasActivePolicy = true;
    sHealth.schemaVersion = HAWK_MAC_POLICY_HEALTH_SCHEMA_VERSION;
    sHealth.active = true;
    sHealth.authenticatedPeer = admission->authenticatedPeer;
    sHealth.signatureVerified = admission->signatureVerified;
    sHealth.signerPinVerified = admission->signerPinVerified;
    sHealth.configurationIntegrityValid = admission->configurationIntegrityValid;
    sHealth.policyEpoch = snapshot->policyEpoch;
    sHealth.deliverySequence = admission->deliverySequence;
    sHealth.expiresAtMonotonicNs = snapshot->expiresAtMonotonicNs;
    sHealth.issuedAtUnixSeconds = admission->issuedAtUnixSeconds;
    sHealth.expiresAtUnixSeconds = admission->expiresAtUnixSeconds;
    sHealth.mode = admission->mode;
    sHealth.policyCurrent = true;
    sHealth.acceptedDeliveryCount += 1;
    sHealth.lastRejectionReason = HAWK_MAC_POLICY_REJECTION_NONE;
    memcpy(sHealth.bundleDigest, admission->bundleDigest, HAWK_FLOOR_HASH_BYTES);
    memcpy(sHealth.policyVersion, snapshot->policyVersion, HAWK_FLOOR_REFERENCE_BYTES);
    HawkMacPolicyEpochObserver observer = sPolicyEpochObserver;
    void *observerContext = sPolicyEpochObserverContext;
    os_unfair_lock_unlock(&sPolicyLock);
    if (observer != NULL && previousPolicyEpoch != snapshot->policyEpoch) {
        observer(previousPolicyEpoch, snapshot->policyEpoch, observerContext);
    }
    return true;
}

static HawkFloorDecision HawkNoPolicyDecision(void) {
    HawkFloorDecision decision;
    memset(&decision, 0, sizeof(decision));
    decision.action = HAWK_FLOOR_ACTION_ALLOW;
    decision.policyAccepted = false;
    return decision;
}

static bool HawkIdentityInSlot(
    const HawkMacPolicySlot *slot,
    const uint8_t identity[HAWK_FLOOR_HASH_BYTES]
) {
    if (slot == NULL || identity == NULL) return false;
    for (uint32_t index = 0; index < slot->governedIdentityCount; ++index) {
        if (HawkBytesEqual(slot->governedIdentities[index], identity, HAWK_FLOOR_HASH_BYTES)) {
            return true;
        }
    }
    return false;
}

static uint32_t HawkClassificationForReference(
    const uint8_t (*references)[HAWK_FLOOR_HASH_BYTES],
    const uint32_t *masks,
    uint32_t count,
    const uint8_t reference[HAWK_FLOOR_HASH_BYTES]
) {
    if (references == NULL || masks == NULL || reference == NULL) return 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (HawkBytesEqual(references[index], reference, HAWK_FLOOR_HASH_BYTES)) {
            return masks[index];
        }
    }
    return 0;
}

static void HawkApplyClassifications(
    const HawkMacPolicySlot *slot,
    HawkFloorRequest *request
) {
    if (slot == NULL || request == NULL) return;
    request->resourceClassification = HawkClassificationForReference(
        slot->resourceReferences, slot->resourceMasks,
        slot->resourceClassificationCount, request->resourceReferenceHash);
    request->destinationClassification = HawkClassificationForReference(
        slot->destinationReferences, slot->destinationMasks,
        slot->destinationClassificationCount, request->destinationReferenceHash);
}

static bool HawkAttachBrokeredPermit(
    const HawkFloorPolicySnapshot *snapshot,
    HawkFloorRequest *request,
    uint64_t nowMonotonicNs
) {
    if (snapshot == NULL || request == NULL || request->permitPresent) {
        return false;
    }
    for (uint32_t index = 0; index < snapshot->permitCount; ++index) {
        const HawkFloorPermit *permit = &snapshot->permits[index];
        if (!permit->integrityVerified ||
            permit->primitive != request->primitive ||
            permit->requestedRights != request->requestedRights ||
            permit->policyEpoch != request->policyEpoch ||
            permit->expiresAtMonotonicNs <= nowMonotonicNs ||
            permit->maximumUses == 0 ||
            permit->consumedUses >= permit->maximumUses ||
            !HawkBytesEqual(
                permit->processInstanceHash,
                request->processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            ) ||
            !HawkBytesEqual(
                permit->stableResourceIdentityHash,
                request->stableResourceIdentityHash,
                HAWK_FLOOR_HASH_BYTES
            ) ||
            !HawkBytesEqual(
                permit->destinationReferenceHash,
                request->destinationReferenceHash,
                HAWK_FLOOR_HASH_BYTES
            ) ||
            !HawkBytesEqual(
                permit->canonicalActionHash,
                request->canonicalActionHash,
                HAWK_FLOOR_HASH_BYTES
            )) {
            continue;
        }
        memcpy(
            request->permitDigest,
            permit->permitDigest,
            HAWK_FLOOR_HASH_BYTES
        );
        request->permitPresent = true;
        return true;
    }
    return false;
}

HawkFloorDecision HawkEvaluateCurrentFloorRequest(
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
) {
    if (request == NULL) {
        return HawkNoPolicyDecision();
    }
    os_unfair_lock_lock(&sPolicyLock);
    HawkFloorDecision decision = HawkNoPolicyDecision();
    if (sHasActivePolicy) {
        HawkMacPolicySlot *slot = &sPolicySlots[sActiveSlot];
        HawkFloorPolicySnapshot *snapshot = &slot->snapshot;
        HawkFloorRequest classifiedRequest = *request;
        HawkApplyClassifications(slot, &classifiedRequest);
        const bool governed = HawkIdentityInSlot(slot, classifiedRequest.binaryIdentityHash);
        const bool expired = nowMonotonicNs >= snapshot->expiresAtMonotonicNs;
        sHealth.policyCurrent = !expired;
        if (!governed) {
            sHealth.ungovernedAllowCount += 1;
            decision = HawkNoPolicyDecision();
        } else if (expired && governed) {
            memset(&decision, 0, sizeof(decision));
            decision.action = HAWK_FLOOR_ACTION_BLOCK;
            decision.policyAccepted = false;
        } else {
            decision = HawkFloorEvaluate(snapshot, &classifiedRequest, nowMonotonicNs);
        }
        if (slot->mode == HAWK_MAC_ENFORCEMENT_DISARMED) {
            decision = HawkNoPolicyDecision();
        } else if (slot->mode == HAWK_MAC_ENFORCEMENT_MONITOR &&
                   decision.action != HAWK_FLOOR_ACTION_ALLOW &&
                   decision.action != HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE) {
            sHealth.wouldBlockCount += 1;
            decision.action = HAWK_FLOOR_ACTION_ALLOW;
        }
        if (!request->permitPresent &&
            decision.action == HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT) {
            HawkFloorRequest brokeredRequest = *request;
            if (HawkAttachBrokeredPermit(
                    snapshot,
                    &brokeredRequest,
                    nowMonotonicNs
                )) {
                decision = HawkFloorEvaluate(
                    snapshot,
                    &brokeredRequest,
                    nowMonotonicNs
                );
                memset(&brokeredRequest, 0, sizeof(brokeredRequest));
            }
        }
    }
    os_unfair_lock_unlock(&sPolicyLock);
    return decision;
}

bool HawkMacIsBinaryIdentityGoverned(
    const uint8_t binaryIdentityHash[HAWK_FLOOR_HASH_BYTES]
) {
    if (binaryIdentityHash == NULL) return false;
    os_unfair_lock_lock(&sPolicyLock);
    const bool result = sHasActivePolicy &&
        HawkIdentityInSlot(&sPolicySlots[sActiveSlot], binaryIdentityHash);
    os_unfair_lock_unlock(&sPolicyLock);
    return result;
}

HawkMacEnforcementMode HawkMacCurrentEnforcementMode(void) {
    os_unfair_lock_lock(&sPolicyLock);
    const HawkMacEnforcementMode mode = sHasActivePolicy
        ? sPolicySlots[sActiveSlot].mode : HAWK_MAC_ENFORCEMENT_DISARMED;
    os_unfair_lock_unlock(&sPolicyLock);
    return mode;
}

bool HawkMacCopyPolicyBinding(
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES],
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES],
    uint64_t *policyEpoch
) {
    if (tenantHash == NULL || deviceHash == NULL || policyEpoch == NULL) {
        return false;
    }
    os_unfair_lock_lock(&sPolicyLock);
    if (!sHasActivePolicy) {
        os_unfair_lock_unlock(&sPolicyLock);
        return false;
    }
    const HawkFloorPolicySnapshot *snapshot = &sPolicySlots[sActiveSlot].snapshot;
    memcpy(tenantHash, snapshot->tenantHash, HAWK_FLOOR_HASH_BYTES);
    memcpy(deviceHash, snapshot->deviceHash, HAWK_FLOOR_HASH_BYTES);
    *policyEpoch = snapshot->policyEpoch;
    os_unfair_lock_unlock(&sPolicyLock);
    return true;
}

bool HawkMacCopyPolicyHealth(HawkMacPolicyHealth *health) {
    if (health == NULL) {
        return false;
    }
    os_unfair_lock_lock(&sPolicyLock);
    memcpy(health, &sHealth, sizeof(*health));
    const time_t unixNow = time(NULL);
    mach_timebase_info_data_t timebase;
    uint64_t monotonicNow = 0;
    if (mach_timebase_info(&timebase) == KERN_SUCCESS && timebase.denom != 0) {
        const __uint128_t scaled = (__uint128_t)mach_absolute_time() * timebase.numer;
        monotonicNow = (uint64_t)(scaled / timebase.denom);
    }
    health->policyCurrent = sHasActivePolicy && unixNow > 0 &&
        sHealth.expiresAtUnixSeconds > (uint64_t)unixNow &&
        sHealth.issuedAtUnixSeconds <= (uint64_t)unixNow + 60ULL &&
        monotonicNow != 0 && monotonicNow < sHealth.expiresAtMonotonicNs;
    os_unfair_lock_unlock(&sPolicyLock);
    return true;
}

void HawkMacSetPolicyEpochObserver(
    HawkMacPolicyEpochObserver observer,
    void *context
) {
    os_unfair_lock_lock(&sPolicyLock);
    sPolicyEpochObserver = observer;
    sPolicyEpochObserverContext = context;
    os_unfair_lock_unlock(&sPolicyLock);
}

const HawkFloorPolicySnapshot *HawkCurrentSignedPolicySnapshot(void) {
    const HawkFloorPolicySnapshot *snapshot = NULL;
    os_unfair_lock_lock(&sPolicyLock);
    if (sHasActivePolicy) {
        snapshot = &sPolicySlots[sActiveSlot].snapshot;
    }
    os_unfair_lock_unlock(&sPolicyLock);
    return snapshot;
}

#if defined(HAWK_MAC_POLICY_TESTING)
void HawkMacClearPolicySnapshotForTesting(void) {
    os_unfair_lock_lock(&sPolicyLock);
    memset(sPolicySlots, 0, sizeof(sPolicySlots));
    memset(&sHealth, 0, sizeof(sHealth));
    sHealth.schemaVersion = HAWK_MAC_POLICY_HEALTH_SCHEMA_VERSION;
    sActiveSlot = 0;
    sHasActivePolicy = false;
    os_unfair_lock_unlock(&sPolicyLock);
}
#endif
