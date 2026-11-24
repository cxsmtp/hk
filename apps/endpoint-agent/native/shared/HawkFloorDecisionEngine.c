#include "HawkFloorDecisionEngine.h"

#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static HawkFloorDecision HawkBlockedDecision(
    bool deadlineExceeded,
    bool policyAccepted,
    bool permitMismatch
) {
    HawkFloorDecision decision;
    memset(&decision, 0, sizeof(decision));
    decision.action = HAWK_FLOOR_ACTION_BLOCK;
    decision.deadlineExceeded = deadlineExceeded;
    decision.policyAccepted = policyAccepted;
    decision.permitMismatch = permitMismatch;
    return decision;
}

static bool HawkBytesEqual(const uint8_t *left, const uint8_t *right, size_t count) {
    uint8_t difference = 0;
    for (size_t index = 0; index < count; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static bool HawkBytesAllZero(const uint8_t *value, size_t count) {
    uint8_t combined = 0;
    for (size_t index = 0; index < count; ++index) {
        combined |= value[index];
    }
    return combined == 0;
}

static bool HawkPrimitiveValid(HawkFloorPrimitive primitive) {
    return primitive >= HAWK_FLOOR_FILE_OPEN && primitive < HAWK_FLOOR_PRIMITIVE_COUNT;
}

static bool HawkActionValid(HawkFloorAction action) {
    return action >= HAWK_FLOOR_ACTION_ALLOW &&
        action <= HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE;
}

static bool HawkAtomicConsumeBounded(volatile uint32_t *consumedUses, uint32_t maximumUses) {
    if (consumedUses == NULL || maximumUses == 0) {
        return false;
    }
#if defined(_MSC_VER)
    for (;;) {
        const long observed = _InterlockedCompareExchange((volatile long *)consumedUses, 0, 0);
        if (observed < 0 || (uint32_t)observed >= maximumUses) {
            return false;
        }
        if (_InterlockedCompareExchange(
                (volatile long *)consumedUses,
                observed + 1,
                observed
            ) == observed) {
            return true;
        }
    }
#else
    uint32_t observed = __atomic_load_n(consumedUses, __ATOMIC_ACQUIRE);
    for (;;) {
        if (observed >= maximumUses) {
            return false;
        }
        if (__atomic_compare_exchange_n(
                consumedUses,
                &observed,
                observed + 1,
                false,
                __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE
            )) {
            return true;
        }
    }
#endif
}

static bool HawkRuleMatches(const HawkFloorRule *rule, const HawkFloorRequest *request) {
    if ((rule->primitiveMask & (1ULL << (uint32_t)request->primitive)) == 0) {
        return false;
    }
    if (rule->resourceClassificationMask != 0 &&
        (rule->resourceClassificationMask & request->resourceClassification) == 0) {
        return false;
    }
    if (rule->destinationClassificationMask != 0 &&
        (rule->destinationClassificationMask & request->destinationClassification) == 0) {
        return false;
    }
    if (rule->businessPurpose != 0 && rule->businessPurpose != request->businessPurpose) {
        return false;
    }
    if (rule->bindBinaryIdentity &&
        !HawkBytesEqual(
            rule->binaryIdentityHash,
            request->binaryIdentityHash,
            HAWK_FLOOR_HASH_BYTES
        )) {
        return false;
    }
    return true;
}

static bool HawkPermitMaterialMatches(
    const HawkFloorPermit *permit,
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
) {
    return permit->integrityVerified &&
        HawkPrimitiveValid(permit->primitive) &&
        permit->primitive == request->primitive &&
        permit->requestedRights == request->requestedRights &&
        permit->policyEpoch == request->policyEpoch &&
        permit->expiresAtMonotonicNs > nowMonotonicNs &&
        permit->maximumUses > 0 &&
        HawkBytesEqual(
            permit->processInstanceHash,
            request->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkBytesEqual(
            permit->stableResourceIdentityHash,
            request->stableResourceIdentityHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkBytesEqual(
            permit->destinationReferenceHash,
            request->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkBytesEqual(
            permit->canonicalActionHash,
            request->canonicalActionHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkBytesEqual(
            permit->permitDigest,
            request->permitDigest,
            HAWK_FLOOR_HASH_BYTES
        );
}

static HawkFloorDecision HawkEvaluatePermit(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
) {
    for (uint32_t index = 0; index < snapshot->permitCount; ++index) {
        HawkFloorPermit *permit = &snapshot->permits[index];
        if (!HawkPermitMaterialMatches(permit, request, nowMonotonicNs)) {
            continue;
        }
        if (!HawkAtomicConsumeBounded(&permit->consumedUses, permit->maximumUses)) {
            return HawkBlockedDecision(false, true, true);
        }
        HawkFloorDecision decision;
        memset(&decision, 0, sizeof(decision));
        decision.action = HAWK_FLOOR_ACTION_ALLOW;
        decision.policyAccepted = true;
        decision.permitConsumed = true;
        memcpy(decision.policyVersion, snapshot->policyVersion, HAWK_FLOOR_REFERENCE_BYTES);
        return decision;
    }
    return HawkBlockedDecision(false, true, true);
}

HawkFloorDecision HawkFloorEvaluate(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
) {
    if (snapshot == NULL || request == NULL ||
        snapshot->schemaVersion != HAWK_FLOOR_SCHEMA_VERSION ||
        request->schemaVersion != HAWK_FLOOR_SCHEMA_VERSION ||
        !snapshot->signatureVerified ||
        !snapshot->configurationIntegrityValid ||
        snapshot->policyEpoch == 0 ||
        request->policyEpoch != snapshot->policyEpoch ||
        snapshot->ruleCount > HAWK_FLOOR_MAX_RULES ||
        (snapshot->ruleCount > 0 && snapshot->rules == NULL) ||
        snapshot->permitCount > HAWK_FLOOR_MAX_PERMITS ||
        (snapshot->permitCount > 0 && snapshot->permits == NULL) ||
        !HawkPrimitiveValid(request->primitive) ||
        HawkBytesAllZero(snapshot->tenantHash, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(snapshot->deviceHash, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(request->processInstanceHash, HAWK_FLOOR_HASH_BYTES) ||
        !HawkBytesEqual(
            snapshot->tenantHash,
            request->tenantHash,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        !HawkBytesEqual(
            snapshot->deviceHash,
            request->deviceHash,
            HAWK_FLOOR_HASH_BYTES
        )) {
        return HawkBlockedDecision(false, false, request != NULL && request->permitPresent);
    }
    if (nowMonotonicNs >= snapshot->expiresAtMonotonicNs ||
        (request->deadlineMonotonicNs != 0 &&
            nowMonotonicNs >= request->deadlineMonotonicNs)) {
        return HawkBlockedDecision(true, false, request->permitPresent);
    }
    if (request->permitPresent) {
        if (request->requestedRights == 0 ||
            HawkBytesAllZero(request->canonicalActionHash, HAWK_FLOOR_HASH_BYTES) ||
            HawkBytesAllZero(request->permitDigest, HAWK_FLOOR_HASH_BYTES)) {
            return HawkBlockedDecision(false, true, true);
        }
        return HawkEvaluatePermit(snapshot, request, nowMonotonicNs);
    }
    for (uint32_t index = 0; index < snapshot->ruleCount; ++index) {
        const HawkFloorRule *rule = &snapshot->rules[index];
        if (!HawkActionValid(rule->action)) {
            return HawkBlockedDecision(false, false, false);
        }
        if (!HawkRuleMatches(rule, request)) {
            continue;
        }
        HawkFloorDecision decision;
        memset(&decision, 0, sizeof(decision));
        decision.action = rule->action;
        decision.matchedRule = true;
        decision.policyAccepted = true;
        memcpy(decision.ruleReference, rule->ruleReference, HAWK_FLOOR_REFERENCE_BYTES);
        memcpy(decision.policyVersion, snapshot->policyVersion, HAWK_FLOOR_REFERENCE_BYTES);
        return decision;
    }
    const HawkFloorAction defaultAction =
        snapshot->defaultActionByPrimitive[(uint32_t)request->primitive];
    if (!HawkActionValid(defaultAction)) {
        return HawkBlockedDecision(false, false, false);
    }
    HawkFloorDecision decision;
    memset(&decision, 0, sizeof(decision));
    decision.action = defaultAction;
    decision.policyAccepted = true;
    memcpy(decision.policyVersion, snapshot->policyVersion, HAWK_FLOOR_REFERENCE_BYTES);
    return decision;
}
