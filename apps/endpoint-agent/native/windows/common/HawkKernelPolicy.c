#include <ntddk.h>
#include <fltKernel.h>
#include <fwpsk.h>

#include "../include/HawkKernelPolicy.h"
#include "../include/HawkWindowsNetworkIdentity.h"
#include "HawkSha256.h"

#define HAWK_POLICY_POOL_TAG 'PlkH'
#define HAWK_PROCESS_TABLE_SIZE 16384U
#define HAWK_PROCESS_PROBES 64U
#define HAWK_CLASSIFICATION_UNKNOWN 0x80000000U
#define HAWK_MAX_POLICY_LIFETIME_NS (24ULL * 60ULL * 60ULL * 1000000000ULL)
#define HAWK_MAX_PERMIT_LIFETIME_NS (5ULL * 60ULL * 1000000000ULL)
#define HAWK_POLICY_EXPIRY_RETRY_NS (100ULL * 1000000ULL)
#define HAWK_PERMIT_INDEX_SIZE 8192U
#define HAWK_PERMIT_INDEX_PROBES 64U
#define HAWK_PERMIT_REPLAY_BITMAP_BYTES 131072U
#define HAWK_PERMIT_REPLAY_BITMAP_BITS \
    (HAWK_PERMIT_REPLAY_BITMAP_BYTES * 8U)
#define HAWK_PERMIT_REPLAY_MAX_DIGESTS 32768U
#define HAWK_RIGHT_FILE_OPEN 0x00000001ULL
#define HAWK_RIGHT_FILE_READ 0x00000002ULL
#define HAWK_RIGHT_FILE_WRITE 0x00000004ULL
#define HAWK_RIGHT_FILE_CREATE 0x00000008ULL
#define HAWK_RIGHT_FILE_DELETE 0x00000010ULL
#define HAWK_RIGHT_FILE_RENAME 0x00000020ULL
#define HAWK_RIGHT_FILE_METADATA 0x00000040ULL
#define HAWK_RIGHT_PROCESS_CHILD_CREATE 0x00000001ULL
#define HAWK_RIGHT_PROCESS_EXECUTE 0x00000002ULL

typedef struct HawkPolicyAllocation {
    volatile LONG references;
    volatile LONG releaseQueued;
    WORK_QUEUE_ITEM releaseWorkItem;
    SIZE_T allocationBytes;
    UINT64 generation;
    UINT64 policySequence;
    UCHAR policyFingerprint[HAWK_FLOOR_HASH_BYTES];
    HawkFloorPolicySnapshot snapshot;
    HawkFloorRule rules[1];
} HawkPolicyAllocation;

typedef struct HawkProcessIdentityEntry {
    HANDLE processId;
    UINT64 processStartKey;
    UCHAR binaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN governedLineage;
    BOOLEAN lineageAuthoritative;
    BOOLEAN occupied;
} HawkProcessIdentityEntry;

typedef struct HawkPermitAllocation {
    volatile LONG references;
    volatile LONG releaseQueued;
    WORK_QUEUE_ITEM releaseWorkItem;
    SIZE_T allocationBytes;
    UINT64 policyGeneration;
    UINT64 policySequence;
    UINT64 permitBatchSequence;
    UINT64 armSessionEpoch;
    UCHAR policyFingerprint[HAWK_FLOOR_HASH_BYTES];
    UCHAR tenantHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR deviceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR driverSessionId[16];
    ULONG permitCount;
    ULONG permitIndex[HAWK_PERMIT_INDEX_SIZE];
    HawkFloorPermit permits[1];
} HawkPermitAllocation;

typedef struct HawkPolicyExpiryWorkContext {
    WORK_QUEUE_ITEM workItem;
} HawkPolicyExpiryWorkContext;

static KSPIN_LOCK gHawkPolicyLock;
static KSPIN_LOCK gHawkProcessLock;
static KSPIN_LOCK gHawkPermitLock;
static EX_PUSH_LOCK gHawkControlTransitionLock;
static HawkPolicyAllocation *gHawkPolicy = NULL;
static HawkPermitAllocation *gHawkPermits = NULL;
static UCHAR gHawkPermitReplayBitmap[HAWK_PERMIT_REPLAY_BITMAP_BYTES];
static ULONG gHawkPermitReplayDigestCount = 0;
static HawkProcessIdentityEntry *gHawkProcesses = NULL;
static volatile LONG gHawkPolicyInitialized = 0;
static volatile LONG gHawkPolicyArmed = 0;
static volatile LONG64 gHawkArmSessionEpoch = 0;
static UCHAR gHawkDriverSessionId[16];
static volatile LONG gHawkIdentityCoverageReady = 0;
static volatile LONG64 gHawkIdentityFailureCount = 0;
static volatile LONG64 gHawkAllowCount = 0;
static volatile LONG64 gHawkBlockCount = 0;
static volatile LONG64 gHawkPolicyRejectCount = 0;
static volatile LONG gHawkDeferredReleaseCount = 0;
static KEVENT gHawkDeferredReleaseEvent;
static KTIMER gHawkPolicyExpiryTimer;
static KDPC gHawkPolicyExpiryDpc;
static KEVENT gHawkPolicyExpiryIdleEvent;
static EX_RUNDOWN_REF gHawkPolicyExpiryRundown;
static volatile LONG gHawkPolicyExpiryWorkQueued = 0;
static volatile LONG gHawkPolicyExpiryWorkPending = 0;
static volatile LONG gHawkPolicyExpiryStopping = 0;

static BOOLEAN HawkCrossGovernedFamilyConflict(
    BOOLEAN actorGovernedLineage,
    const UCHAR actorPolicyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    BOOLEAN targetDirectlyGoverned,
    const UCHAR targetActualBinaryHash[HAWK_FLOOR_HASH_BYTES]
);
static HawkPolicyAllocation *HawkAcquirePolicy(VOID);
static VOID HawkReleasePolicy(_In_opt_ HawkPolicyAllocation *policy);
static VOID HawkSchedulePolicyExpiry(UINT64 validForNanoseconds);
static VOID HawkQueuePolicyExpiryWork(VOID);

static BOOLEAN HawkPolicyIsArmed(VOID) {
    return InterlockedCompareExchange(&gHawkPolicyArmed, 0, 0) != 0;
}

static VOID HawkAcquireControlTransitionLock(VOID) {
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gHawkControlTransitionLock);
}

static VOID HawkReleaseControlTransitionLock(VOID) {
    ExReleasePushLockExclusive(&gHawkControlTransitionLock);
    KeLeaveCriticalRegion();
}

BOOLEAN HawkEnforcementArmed(VOID) {
    return HawkPolicyIsArmed();
}

static NTSTATUS HawkRejectPolicy(NTSTATUS status) {
    InterlockedIncrement64(&gHawkPolicyRejectCount);
    return status;
}

static UINT64 HawkMonotonicNanoseconds(VOID) {
    return KeQueryInterruptTime() * 100ULL;
}

static BOOLEAN HawkPolicyNeedsNetwork(
    const HawkPolicyAllocation *policy
) {
    if (policy == NULL) return FALSE;
    for (ULONG index = 0; index < policy->snapshot.ruleCount; ++index) {
        if ((policy->rules[index].primitiveMask &
            (1ULL << (UINT32)HAWK_FLOOR_NETWORK_CONNECT)) != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID HawkPolicyExpiryWorker(PVOID context) {
    HawkPolicyExpiryWorkContext *workContext = context;
    if (InterlockedCompareExchange(&gHawkPolicyExpiryStopping, 0, 0) == 0) {
        /*
         * Serialize with policy publication. The worker must never re-arm the
         * timer from an obsolete snapshot after a short-lived replacement has
         * already installed its own expiry.
         */
        HawkAcquireControlTransitionLock();
        HawkPolicyAllocation *policy = HawkAcquirePolicy();
        if (policy != NULL && HawkPolicyIsArmed()) {
            const UINT64 now = HawkMonotonicNanoseconds();
            if (policy->snapshot.expiresAtMonotonicNs <= now) {
                /*
                 * WFP management is PASSIVE_LEVEL-only. Swapping the active
                 * ALE filter bank forces every existing TCP/UDP flow to
                 * re-enter the local evaluator on its next packet, where the
                 * expired snapshot fails closed. A transition failure drops
                 * WFP health immediately and is retried by this bounded timer;
                 * it never converts into a stale green state.
                 */
                if (HawkPolicyNeedsNetwork(policy) &&
                    !NT_SUCCESS(HawkWfpReauthorizeFlows())) {
                    InterlockedIncrement64(&gHawkPolicyRejectCount);
                    HawkSchedulePolicyExpiry(HAWK_POLICY_EXPIRY_RETRY_NS);
                }
            } else {
                HawkSchedulePolicyExpiry(
                    policy->snapshot.expiresAtMonotonicNs - now
                );
            }
        }
        HawkReleasePolicy(policy);
        HawkReleaseControlTransitionLock();
    }
    InterlockedExchange(&gHawkPolicyExpiryWorkQueued, 0);
    if (InterlockedExchange(&gHawkPolicyExpiryWorkPending, 0) != 0 &&
        InterlockedCompareExchange(
            &gHawkPolicyExpiryStopping,
            0,
            0
        ) == 0) {
        /*
         * Each queued callback owns a distinct nonpaged work item, so a DPC
         * collision can never requeue storage that is still executing.
         */
        HawkQueuePolicyExpiryWork();
    }
    if (InterlockedCompareExchange(
            &gHawkPolicyExpiryWorkQueued,
            0,
            0
        ) == 0) {
        KeSetEvent(&gHawkPolicyExpiryIdleEvent, IO_NO_INCREMENT, FALSE);
    }
    ExFreePoolWithTag(workContext, HAWK_POLICY_POOL_TAG);
    ExReleaseRundownProtection(&gHawkPolicyExpiryRundown);
}

static VOID HawkQueuePolicyExpiryWork(VOID) {
    if (InterlockedCompareExchange(&gHawkPolicyExpiryStopping, 0, 0) != 0) {
        return;
    }
    if (!ExAcquireRundownProtection(&gHawkPolicyExpiryRundown)) return;
    if (InterlockedCompareExchange(
            &gHawkPolicyExpiryWorkQueued,
            1,
            0
        ) != 0) {
        InterlockedExchange(&gHawkPolicyExpiryWorkPending, 1);
        ExReleaseRundownProtection(&gHawkPolicyExpiryRundown);
        return;
    }
    HawkPolicyExpiryWorkContext *workContext = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*workContext),
        HAWK_POLICY_POOL_TAG
    );
    if (workContext == NULL) {
        InterlockedIncrement64(&gHawkPolicyRejectCount);
        InterlockedExchange(&gHawkPolicyExpiryWorkQueued, 0);
        KeSetEvent(&gHawkPolicyExpiryIdleEvent, IO_NO_INCREMENT, FALSE);
        HawkSchedulePolicyExpiry(HAWK_POLICY_EXPIRY_RETRY_NS);
        ExReleaseRundownProtection(&gHawkPolicyExpiryRundown);
        return;
    }
    KeClearEvent(&gHawkPolicyExpiryIdleEvent);
    ExInitializeWorkItem(
        &workContext->workItem,
        HawkPolicyExpiryWorker,
        workContext
    );
    ExQueueWorkItem(&workContext->workItem, DelayedWorkQueue);
}

static VOID HawkPolicyExpiryDpc(
    _In_ KDPC *dpc,
    _In_opt_ PVOID deferredContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2
) {
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(deferredContext);
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);
    HawkQueuePolicyExpiryWork();
}

static VOID HawkSchedulePolicyExpiry(UINT64 validForNanoseconds) {
    if (validForNanoseconds == 0 ||
        InterlockedCompareExchange(&gHawkPolicyExpiryStopping, 0, 0) != 0) {
        return;
    }
    UINT64 relativeHundredNanoseconds =
        (validForNanoseconds + 99ULL) / 100ULL;
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -(LONGLONG)relativeHundredNanoseconds;
    (VOID)KeSetTimer(
        &gHawkPolicyExpiryTimer,
        dueTime,
        &gHawkPolicyExpiryDpc
    );
}

static BOOLEAN HawkBytesEqual(const UCHAR *left, const UCHAR *right, SIZE_T length) {
    UCHAR difference = 0;
    for (SIZE_T index = 0; index < length; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static BOOLEAN HawkBytesAllZero(const UCHAR *value, SIZE_T length) {
    UCHAR combined = 0;
    for (SIZE_T index = 0; index < length; ++index) combined |= value[index];
    return combined == 0;
}

static BOOLEAN HawkBytesLexicographicLess(
    const UCHAR *left,
    const UCHAR *right,
    SIZE_T length
) {
    for (SIZE_T index = 0; index < length; ++index) {
        if (left[index] < right[index]) return TRUE;
        if (left[index] > right[index]) return FALSE;
    }
    return FALSE;
}

static UINT32 HawkDigestWord(
    const UCHAR digest[HAWK_FLOOR_HASH_BYTES],
    ULONG offset
) {
    return (UINT32)digest[offset] |
        ((UINT32)digest[offset + 1U] << 8U) |
        ((UINT32)digest[offset + 2U] << 16U) |
        ((UINT32)digest[offset + 3U] << 24U);
}

static ULONG HawkPermitIndexSlot(
    const UCHAR canonicalActionHash[HAWK_FLOOR_HASH_BYTES],
    ULONG probe
) {
    const ULONG initial = HawkDigestWord(canonicalActionHash, 0) &
        (HAWK_PERMIT_INDEX_SIZE - 1U);
    const ULONG step = (HawkDigestWord(canonicalActionHash, 4) | 1U) &
        (HAWK_PERMIT_INDEX_SIZE - 1U);
    return (initial + probe * step) & (HAWK_PERMIT_INDEX_SIZE - 1U);
}

static BOOLEAN HawkBuildPermitIndex(HawkPermitAllocation *permits) {
    if (permits == NULL || permits->permitCount > HAWK_FLOOR_MAX_PERMITS) {
        return FALSE;
    }
    RtlZeroMemory(permits->permitIndex, sizeof(permits->permitIndex));
    for (ULONG index = 0; index < permits->permitCount; ++index) {
        BOOLEAN inserted = FALSE;
        for (ULONG probe = 0; probe < HAWK_PERMIT_INDEX_PROBES; ++probe) {
            const ULONG slot = HawkPermitIndexSlot(
                permits->permits[index].canonicalActionHash,
                probe
            );
            const ULONG encodedIndex = permits->permitIndex[slot];
            if (encodedIndex == 0) {
                permits->permitIndex[slot] = index + 1U;
                inserted = TRUE;
                break;
            }
            const ULONG existingIndex = encodedIndex - 1U;
            if (existingIndex >= permits->permitCount || HawkBytesEqual(
                    permits->permits[existingIndex].canonicalActionHash,
                    permits->permits[index].canonicalActionHash,
                    HAWK_FLOOR_HASH_BYTES
                )) {
                return FALSE;
            }
        }
        if (!inserted) return FALSE;
    }
    return TRUE;
}

static HawkFloorPermit *HawkFindIndexedPermit(
    HawkPermitAllocation *permits,
    const UCHAR canonicalActionHash[HAWK_FLOOR_HASH_BYTES]
) {
    if (permits == NULL ||
        HawkBytesAllZero(canonicalActionHash, HAWK_FLOOR_HASH_BYTES)) {
        return NULL;
    }
    for (ULONG probe = 0; probe < HAWK_PERMIT_INDEX_PROBES; ++probe) {
        const ULONG slot = HawkPermitIndexSlot(canonicalActionHash, probe);
        const ULONG encodedIndex = permits->permitIndex[slot];
        if (encodedIndex == 0) return NULL;
        const ULONG index = encodedIndex - 1U;
        if (index >= permits->permitCount) return NULL;
        if (HawkBytesEqual(
                permits->permits[index].canonicalActionHash,
                canonicalActionHash,
                HAWK_FLOOR_HASH_BYTES
            )) {
            return &permits->permits[index];
        }
    }
    return NULL;
}

static BOOLEAN HawkPermitReplaySeen(
    const UCHAR permitDigest[HAWK_FLOOR_HASH_BYTES]
) {
    for (ULONG word = 0; word < 4U; ++word) {
        const ULONG bit = HawkDigestWord(permitDigest, word * 4U) &
            (HAWK_PERMIT_REPLAY_BITMAP_BITS - 1U);
        if ((gHawkPermitReplayBitmap[bit >> 3U] &
            (UCHAR)(1U << (bit & 7U))) == 0) {
            return FALSE;
        }
    }
    return TRUE;
}

static VOID HawkRememberPermitReplayDigest(
    const UCHAR permitDigest[HAWK_FLOOR_HASH_BYTES]
) {
    for (ULONG word = 0; word < 4U; ++word) {
        const ULONG bit = HawkDigestWord(permitDigest, word * 4U) &
            (HAWK_PERMIT_REPLAY_BITMAP_BITS - 1U);
        gHawkPermitReplayBitmap[bit >> 3U] |=
            (UCHAR)(1U << (bit & 7U));
    }
    ++gHawkPermitReplayDigestCount;
}

static BOOLEAN HawkPrimitiveValid(HawkFloorPrimitive primitive) {
    return primitive >= HAWK_FLOOR_FILE_OPEN &&
        primitive < HAWK_FLOOR_PRIMITIVE_COUNT;
}

static BOOLEAN HawkPrimitiveNeedsStableResource(HawkFloorPrimitive primitive) {
    return primitive >= HAWK_FLOOR_FILE_OPEN && primitive <= HAWK_FLOOR_FILE_UNKNOWN;
}

static BOOLEAN HawkPrimitiveNeedsDestination(HawkFloorPrimitive primitive) {
    return primitive >= HAWK_FLOOR_NETWORK_CONNECT &&
        primitive <= HAWK_FLOOR_NETWORK_UNKNOWN;
}

static BOOLEAN HawkPrimitivePermitBindingImplemented(
    HawkFloorPrimitive primitive
) {
    /*
     * Windows exact permits are currently implemented only at the ALE
     * TCP/UDP connect boundary. A minifilter pre-create callback cannot query
     * FileInternalInformation because the target is not open yet, and the
     * process gate does not yet bind a target image generation. Rejecting all
     * other permit entries prevents unusable approvals from consuming replay
     * capacity or being mistaken for exact enforcement.
     */
    return primitive == HAWK_FLOOR_NETWORK_CONNECT;
}

static ULONG HawkProcessSlot(HANDLE processId) {
    return ((ULONG)(ULONG_PTR)processId * 2654435761U) & (HAWK_PROCESS_TABLE_SIZE - 1U);
}

static VOID HawkDeferredReleaseComplete(VOID) {
    if (InterlockedDecrement(&gHawkDeferredReleaseCount) == 0) {
        KeSetEvent(&gHawkDeferredReleaseEvent, IO_NO_INCREMENT, FALSE);
    }
}

static VOID HawkReleasePolicyWorker(PVOID context) {
    HawkPolicyAllocation *policy = context;
    const SIZE_T allocationBytes = policy->allocationBytes;
    RtlSecureZeroMemory(policy, allocationBytes);
    ExFreePoolWithTag(policy, HAWK_POLICY_POOL_TAG);
    HawkDeferredReleaseComplete();
}

static VOID HawkReleasePolicy(HawkPolicyAllocation *policy) {
    if (policy == NULL || InterlockedDecrement(&policy->references) != 0) return;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        const SIZE_T allocationBytes = policy->allocationBytes;
        RtlSecureZeroMemory(policy, allocationBytes);
        ExFreePoolWithTag(policy, HAWK_POLICY_POOL_TAG);
        return;
    }
    if (InterlockedCompareExchange(&policy->releaseQueued, 1, 0) == 0) {
        if (InterlockedIncrement(&gHawkDeferredReleaseCount) == 1) {
            KeClearEvent(&gHawkDeferredReleaseEvent);
        }
        ExInitializeWorkItem(
            &policy->releaseWorkItem,
            HawkReleasePolicyWorker,
            policy
        );
        ExQueueWorkItem(&policy->releaseWorkItem, DelayedWorkQueue);
    }
}

static HawkPolicyAllocation *HawkAcquirePolicy(VOID) {
    KIRQL oldIrql;
    HawkPolicyAllocation *policy;
    KeAcquireSpinLock(&gHawkPolicyLock, &oldIrql);
    policy = gHawkPolicy;
    if (policy != NULL) InterlockedIncrement(&policy->references);
    KeReleaseSpinLock(&gHawkPolicyLock, oldIrql);
    return policy;
}

static VOID HawkReleasePermitWorker(PVOID context) {
    HawkPermitAllocation *permits = context;
    const SIZE_T allocationBytes = permits->allocationBytes;
    RtlSecureZeroMemory(permits, allocationBytes);
    ExFreePoolWithTag(permits, HAWK_POLICY_POOL_TAG);
    HawkDeferredReleaseComplete();
}

static VOID HawkReleasePermits(HawkPermitAllocation *permits) {
    if (permits == NULL || InterlockedDecrement(&permits->references) != 0) return;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        const SIZE_T allocationBytes = permits->allocationBytes;
        RtlSecureZeroMemory(permits, allocationBytes);
        ExFreePoolWithTag(permits, HAWK_POLICY_POOL_TAG);
        return;
    }
    if (InterlockedCompareExchange(&permits->releaseQueued, 1, 0) == 0) {
        if (InterlockedIncrement(&gHawkDeferredReleaseCount) == 1) {
            KeClearEvent(&gHawkDeferredReleaseEvent);
        }
        ExInitializeWorkItem(
            &permits->releaseWorkItem,
            HawkReleasePermitWorker,
            permits
        );
        ExQueueWorkItem(&permits->releaseWorkItem, DelayedWorkQueue);
    }
}

static HawkPermitAllocation *HawkAcquirePermits(VOID) {
    KIRQL oldIrql;
    HawkPermitAllocation *permits;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    permits = gHawkPermits;
    if (permits != NULL) InterlockedIncrement(&permits->references);
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    return permits;
}

static VOID HawkClearPermits(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    HawkPermitAllocation *old = gHawkPermits;
    gHawkPermits = NULL;
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    HawkReleasePermits(old);
    RtlSecureZeroMemory(
        gHawkPermitReplayBitmap,
        sizeof(gHawkPermitReplayBitmap)
    );
    gHawkPermitReplayDigestCount = 0;
}

static UINT64 HawkAdvanceArmSessionEpoch(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    InterlockedExchange(&gHawkPolicyArmed, 0);
    LONG64 next = InterlockedIncrement64(&gHawkArmSessionEpoch);
    if (next <= 0) {
        InterlockedExchange64(&gHawkArmSessionEpoch, 1);
        next = 1;
    }
    HawkPermitAllocation *permits = gHawkPermits;
    gHawkPermits = NULL;
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    HawkReleasePermits(permits);
    return (UINT64)next;
}

static UINT64 HawkInvalidateArmAuthorityPreserveEnforcement(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    LONG64 next = InterlockedIncrement64(&gHawkArmSessionEpoch);
    if (next <= 0) {
        InterlockedExchange64(&gHawkArmSessionEpoch, 1);
        next = 1;
    }
    HawkPermitAllocation *permits = gHawkPermits;
    gHawkPermits = NULL;
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    HawkReleasePermits(permits);
    /* A material policy change starts a new replay domain. */
    RtlSecureZeroMemory(
        gHawkPermitReplayBitmap,
        sizeof(gHawkPermitReplayBitmap)
    );
    gHawkPermitReplayDigestCount = 0;
    return (UINT64)next;
}

static BOOLEAN HawkCommitArmSession(UINT64 expectedEpoch) {
    BOOLEAN committed = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    if ((UINT64)InterlockedCompareExchange64(
            &gHawkArmSessionEpoch,
            0,
            0
        ) == expectedEpoch && !HawkPolicyIsArmed()) {
        InterlockedExchange(&gHawkPolicyArmed, 1);
        committed = TRUE;
    }
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    return committed;
}

static BOOLEAN HawkCaptureArmSessionEpoch(UINT64 *armSessionEpoch) {
    if (armSessionEpoch == NULL) return FALSE;
    BOOLEAN armed = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    if (HawkPolicyIsArmed()) {
        *armSessionEpoch = (UINT64)InterlockedCompareExchange64(
            &gHawkArmSessionEpoch,
            0,
            0
        );
        armed = *armSessionEpoch != 0;
    }
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    return armed;
}

static BOOLEAN HawkArmSessionCurrent(UINT64 expectedEpoch) {
    BOOLEAN current;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
    current = HawkPolicyIsArmed() && expectedEpoch != 0 &&
        (UINT64)InterlockedCompareExchange64(
            &gHawkArmSessionEpoch,
            0,
            0
        ) == expectedEpoch;
    KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
    return current;
}

BOOLEAN HawkLookupProcessIdentity(
    HANDLE processId,
    UCHAR actualBinaryHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES],
    BOOLEAN *governedLineage,
    BOOLEAN *lineageAuthoritative
) {
    if (gHawkProcesses == NULL || processId == NULL ||
        actualBinaryHash == NULL || policyBinaryHash == NULL ||
        processInstanceHash == NULL || familyRootInstanceHash == NULL ||
        governedLineage == NULL || lineageAuthoritative == NULL) return FALSE;
    BOOLEAN found = FALSE;
    const ULONG initial = HawkProcessSlot(processId);
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkProcessLock, &oldIrql);
    for (ULONG probe = 0; probe < HAWK_PROCESS_PROBES; ++probe) {
        HawkProcessIdentityEntry *entry = &gHawkProcesses[(initial + probe) & (HAWK_PROCESS_TABLE_SIZE - 1U)];
        if (entry->occupied && entry->processId == processId) {
            RtlCopyMemory(
                actualBinaryHash,
                entry->binaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                policyBinaryHash,
                entry->policyBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                processInstanceHash,
                entry->processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                familyRootInstanceHash,
                entry->familyRootInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
            *governedLineage = entry->governedLineage;
            *lineageAuthoritative = entry->lineageAuthoritative;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gHawkProcessLock, oldIrql);
    return found;
}

NTSTATUS HawkQueryProcessIdentity(
    UINT64 processIdValue,
    HawkWindowsProcessIdentityResponse *response
) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || processIdValue == 0 ||
        response == NULL || gHawkProcesses == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    const HANDLE processId = (HANDLE)(ULONG_PTR)processIdValue;
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
    if (!NT_SUCCESS(status)) return status;
    const UINT64 processStartKey = PsGetProcessStartKey(process);
    ObDereferenceObject(process);
    if (processStartKey == 0) return STATUS_NOT_FOUND;

    RtlZeroMemory(response, sizeof(*response));
    const ULONG initial = HawkProcessSlot(processId);
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkProcessLock, &oldIrql);
    for (ULONG probe = 0; probe < HAWK_PROCESS_PROBES; ++probe) {
        const HawkProcessIdentityEntry *entry =
            &gHawkProcesses[(initial + probe) & (HAWK_PROCESS_TABLE_SIZE - 1U)];
        if (entry->occupied && entry->processId == processId &&
            entry->processStartKey == processStartKey) {
            response->version = HAWK_WINDOWS_POLICY_VERSION;
            response->processId = processIdValue;
            RtlCopyMemory(
                response->binaryIdentityHash,
                entry->binaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                response->policyBinaryIdentityHash,
                entry->policyBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                response->processInstanceHash,
                entry->processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                response->familyRootInstanceHash,
                entry->familyRootInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
            response->governedLineage = entry->governedLineage ? 1 : 0;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gHawkProcessLock, oldIrql);
    if (!found) {
        RtlSecureZeroMemory(response, sizeof(*response));
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN HawkBuildProcessIdentity(
    HANDLE processId,
    PEPROCESS process,
    PCUNICODE_STRING imageFileName,
    UCHAR binaryHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES]
) {
    if (processId == NULL || process == NULL || imageFileName == NULL ||
        imageFileName->Buffer == NULL || imageFileName->Length == 0) {
        return FALSE;
    }
    struct {
        UCHAR domain[40];
        UINT64 processId;
        UINT64 processStartKey;
        UCHAR binaryHash[HAWK_FLOOR_HASH_BYTES];
    } processMaterial;
    C_ASSERT(sizeof("hawk.windows.process-instance.v1") <=
        sizeof(processMaterial.domain));
    RtlZeroMemory(&processMaterial, sizeof(processMaterial));
    RtlCopyMemory(
        processMaterial.domain,
        "hawk.windows.process-instance.v1",
        sizeof("hawk.windows.process-instance.v1")
    );
    processMaterial.processId = (UINT64)(ULONG_PTR)processId;
    processMaterial.processStartKey = PsGetProcessStartKey(process);
    if (processMaterial.processStartKey == 0) return FALSE;
    HawkSha256UnicodeInsensitive(imageFileName, binaryHash);
    RtlCopyMemory(
        processMaterial.binaryHash,
        binaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    HawkSha256Bytes(
        (const UCHAR *)&processMaterial,
        sizeof(processMaterial),
        processInstanceHash
    );
    RtlSecureZeroMemory(&processMaterial, sizeof(processMaterial));
    return !HawkBytesAllZero(binaryHash, HAWK_FLOOR_HASH_BYTES) &&
        !HawkBytesAllZero(processInstanceHash, HAWK_FLOOR_HASH_BYTES);
}

static BOOLEAN HawkPolicyHashIsGoverned(
    const UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES]
) {
    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    BOOLEAN governed = FALSE;
    if (policy != NULL) {
        for (ULONG index = 0; index < policy->snapshot.ruleCount; ++index) {
            const HawkFloorRule *rule = &policy->snapshot.rules[index];
            if (rule->bindBinaryIdentity && HawkBytesEqual(
                    rule->binaryIdentityHash,
                    policyBinaryHash,
                    HAWK_FLOOR_HASH_BYTES
                )) {
                governed = TRUE;
                break;
            }
        }
    }
    HawkReleasePolicy(policy);
    return governed;
}

static BOOLEAN HawkReadExistingLineage(
    HANDLE processId,
    UINT64 processStartKey,
    const UCHAR actualBinaryHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES],
    BOOLEAN *governedLineage,
    BOOLEAN *lineageAuthoritative
) {
    if (gHawkProcesses == NULL || governedLineage == NULL ||
        lineageAuthoritative == NULL) return FALSE;
    const ULONG initial = HawkProcessSlot(processId);
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkProcessLock, &oldIrql);
    for (ULONG probe = 0; probe < HAWK_PROCESS_PROBES; ++probe) {
        const HawkProcessIdentityEntry *entry =
            &gHawkProcesses[(initial + probe) & (HAWK_PROCESS_TABLE_SIZE - 1U)];
        if (entry->occupied && entry->processId == processId &&
            entry->processStartKey == processStartKey &&
            HawkBytesEqual(
                entry->binaryHash,
                actualBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            )) {
            RtlCopyMemory(
                policyBinaryHash,
                entry->policyBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                familyRootInstanceHash,
                entry->familyRootInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
            *governedLineage = entry->governedLineage;
            *lineageAuthoritative = entry->lineageAuthoritative;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gHawkProcessLock, oldIrql);
    return found;
}

BOOLEAN HawkRememberProcessIdentity(
    HANDLE processId,
    PEPROCESS process,
    PCUNICODE_STRING imageFileName,
    const HawkProcessLineageSeed *lineageSeed
) {
    if (gHawkProcesses == NULL || processId == NULL || process == NULL ||
        imageFileName == NULL ||
        imageFileName->Buffer == NULL || imageFileName->Length == 0) {
        InterlockedExchange(&gHawkIdentityCoverageReady, 0);
        InterlockedIncrement64(&gHawkIdentityFailureCount);
        return FALSE;
    }
    UCHAR binaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    if (!HawkBuildProcessIdentity(
            processId,
            process,
            imageFileName,
            binaryHash,
            processInstanceHash
        )) {
        InterlockedExchange(&gHawkIdentityCoverageReady, 0);
        InterlockedIncrement64(&gHawkIdentityFailureCount);
        return FALSE;
    }
    UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN governedLineage;
    BOOLEAN lineageAuthoritative = FALSE;
    const UINT64 processStartKey = PsGetProcessStartKey(process);
    UCHAR existingPolicyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR existingFamilyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN existingGovernedLineage = FALSE;
    BOOLEAN existingLineageAuthoritative = FALSE;
    const BOOLEAN existingLineage = HawkReadExistingLineage(
        processId,
        processStartKey,
        binaryHash,
        existingPolicyBinaryHash,
        existingFamilyRootInstanceHash,
        &existingGovernedLineage,
        &existingLineageAuthoritative
    );
    const BOOLEAN directlyGoverned = HawkImageIsGoverned(imageFileName);
    if (lineageSeed != NULL) {
        if (!HawkBytesEqual(
                binaryHash,
                lineageSeed->actualBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            ) || !HawkBytesEqual(
                processInstanceHash,
                lineageSeed->processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            ) || HawkBytesAllZero(
                lineageSeed->policyBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            ) || HawkBytesAllZero(
                lineageSeed->familyRootInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            ) || (lineageSeed->allowConservativeAuthorityDowngrade &&
                (!lineageSeed->governedLineage ||
                    lineageSeed->lineageAuthoritative ||
                    !HawkBytesEqual(
                        lineageSeed->policyBinaryHash,
                        lineageSeed->actualBinaryHash,
                        HAWK_FLOOR_HASH_BYTES
                    ) || !HawkBytesEqual(
                        lineageSeed->familyRootInstanceHash,
                        lineageSeed->processInstanceHash,
                        HAWK_FLOOR_HASH_BYTES
                    )))
            ) {
            RtlSecureZeroMemory(binaryHash, sizeof(binaryHash));
            RtlSecureZeroMemory(processInstanceHash, sizeof(processInstanceHash));
            InterlockedExchange(&gHawkIdentityCoverageReady, 0);
            InterlockedIncrement64(&gHawkIdentityFailureCount);
            return FALSE;
        }
        const BOOLEAN preserveExistingAuthority =
            existingLineage && existingLineageAuthoritative &&
            !lineageSeed->allowConservativeAuthorityDowngrade;
        if (preserveExistingAuthority &&
            !lineageSeed->lineageAuthoritative &&
            (existingGovernedLineage != lineageSeed->governedLineage ||
                !HawkBytesEqual(
                    existingPolicyBinaryHash,
                    lineageSeed->policyBinaryHash,
                    HAWK_FLOOR_HASH_BYTES
                ) ||
                !HawkBytesEqual(
                    existingFamilyRootInstanceHash,
                    lineageSeed->familyRootInstanceHash,
                    HAWK_FLOOR_HASH_BYTES
                ))) {
            RtlSecureZeroMemory(binaryHash, sizeof(binaryHash));
            RtlSecureZeroMemory(processInstanceHash, sizeof(processInstanceHash));
            InterlockedExchange(&gHawkIdentityCoverageReady, 0);
            InterlockedIncrement64(&gHawkIdentityFailureCount);
            return FALSE;
        }
        RtlCopyMemory(
            policyBinaryHash,
            lineageSeed->policyBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            familyRootInstanceHash,
            lineageSeed->familyRootInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        governedLineage = lineageSeed->governedLineage;
        lineageAuthoritative =
            lineageSeed->lineageAuthoritative ||
            preserveExistingAuthority;
        if (directlyGoverned && governedLineage && !HawkBytesEqual(
                policyBinaryHash,
                binaryHash,
                HAWK_FLOOR_HASH_BYTES
            )) {
            RtlSecureZeroMemory(binaryHash, sizeof(binaryHash));
            RtlSecureZeroMemory(processInstanceHash, sizeof(processInstanceHash));
            RtlSecureZeroMemory(policyBinaryHash, sizeof(policyBinaryHash));
            RtlSecureZeroMemory(
                familyRootInstanceHash,
                sizeof(familyRootInstanceHash)
            );
            InterlockedExchange(&gHawkIdentityCoverageReady, 0);
            InterlockedIncrement64(&gHawkIdentityFailureCount);
            return FALSE;
        }
    } else if (directlyGoverned) {
        if (existingLineage && existingGovernedLineage &&
            HawkPolicyHashIsGoverned(existingPolicyBinaryHash) &&
            !HawkBytesEqual(
                existingPolicyBinaryHash,
                binaryHash,
                HAWK_FLOOR_HASH_BYTES
            )) {
            RtlSecureZeroMemory(binaryHash, sizeof(binaryHash));
            RtlSecureZeroMemory(processInstanceHash, sizeof(processInstanceHash));
            InterlockedExchange(&gHawkIdentityCoverageReady, 0);
            InterlockedIncrement64(&gHawkIdentityFailureCount);
            return FALSE;
        }
        RtlCopyMemory(policyBinaryHash, binaryHash, HAWK_FLOOR_HASH_BYTES);
        RtlCopyMemory(
            familyRootInstanceHash,
            processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        governedLineage = TRUE;
        lineageAuthoritative = TRUE;
    } else if (existingLineage && existingGovernedLineage &&
        HawkPolicyHashIsGoverned(existingPolicyBinaryHash)) {
        RtlCopyMemory(
            policyBinaryHash,
            existingPolicyBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            familyRootInstanceHash,
            existingFamilyRootInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        governedLineage = TRUE;
        lineageAuthoritative = existingLineageAuthoritative;
    } else {
        RtlCopyMemory(policyBinaryHash, binaryHash, HAWK_FLOOR_HASH_BYTES);
        RtlCopyMemory(
            familyRootInstanceHash,
            processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        governedLineage = FALSE;
        lineageAuthoritative = existingLineage && existingLineageAuthoritative;
    }
    const ULONG initial = HawkProcessSlot(processId);
    BOOLEAN stored = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkProcessLock, &oldIrql);
    for (ULONG probe = 0; probe < HAWK_PROCESS_PROBES; ++probe) {
        HawkProcessIdentityEntry *entry = &gHawkProcesses[(initial + probe) & (HAWK_PROCESS_TABLE_SIZE - 1U)];
        if (!entry->occupied || entry->processId == processId) {
            entry->processId = processId;
            entry->processStartKey = processStartKey;
            RtlCopyMemory(entry->binaryHash, binaryHash, sizeof(binaryHash));
            RtlCopyMemory(
                entry->policyBinaryHash,
                policyBinaryHash,
                sizeof(policyBinaryHash)
            );
            RtlCopyMemory(
                entry->processInstanceHash,
                processInstanceHash,
                sizeof(processInstanceHash)
            );
            RtlCopyMemory(
                entry->familyRootInstanceHash,
                familyRootInstanceHash,
                sizeof(familyRootInstanceHash)
            );
            entry->governedLineage = governedLineage;
            entry->lineageAuthoritative = lineageAuthoritative;
            entry->occupied = TRUE;
            stored = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gHawkProcessLock, oldIrql);
    if (!stored) {
        InterlockedExchange(&gHawkIdentityCoverageReady, 0);
        InterlockedIncrement64(&gHawkIdentityFailureCount);
    }
    RtlSecureZeroMemory(binaryHash, sizeof(binaryHash));
    RtlSecureZeroMemory(policyBinaryHash, sizeof(policyBinaryHash));
    RtlSecureZeroMemory(processInstanceHash, sizeof(processInstanceHash));
    RtlSecureZeroMemory(
        familyRootInstanceHash,
        sizeof(familyRootInstanceHash)
    );
    return stored;
}

BOOLEAN HawkIdentityCoverageReady(VOID) {
    return InterlockedCompareExchange(&gHawkIdentityCoverageReady, 0, 0) != 0;
}

static BOOLEAN HawkRememberAmbiguousOrphanProcess(
    HANDLE processId,
    PEPROCESS process,
    PCUNICODE_STRING imageFileName
) {
    HawkProcessLineageSeed seed;
    RtlZeroMemory(&seed, sizeof(seed));
    if (!HawkBuildProcessIdentity(
            processId,
            process,
            imageFileName,
            seed.actualBinaryHash,
            seed.processInstanceHash
        )) {
        return FALSE;
    }
    /*
     * A live process whose parent identity is unavailable must not prevent the
     * complete service snapshot from arming the floor, but it also must not be
     * laundered into an ungoverned root. Mark the lineage conservatively as
     * governed and non-authoritative. Every policy-relevant consequence from
     * this process (and any propagated child) therefore fails closed until a
     * protected create callback supplies authoritative lineage.
     */
    seed.governedLineage = TRUE;
    seed.lineageAuthoritative = FALSE;
    seed.allowConservativeAuthorityDowngrade = TRUE;
    RtlCopyMemory(
        seed.policyBinaryHash,
        seed.actualBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        seed.familyRootInstanceHash,
        seed.processInstanceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    const BOOLEAN stored = HawkRememberProcessIdentity(
        processId,
        process,
        imageFileName,
        &seed
    );
    RtlSecureZeroMemory(&seed, sizeof(seed));
    return stored;
}

static BOOLEAN HawkRestoreSeededProcessLineage(
    HANDLE processId,
    HANDLE parentProcessId,
    PEPROCESS process,
    PCUNICODE_STRING imageFileName,
    BOOLEAN lineageSourceAuthoritative
) {
    if (parentProcessId == NULL) {
        const BOOLEAN directlyGoverned = HawkImageIsGoverned(imageFileName);
        const HANDLE inheritedParentProcessId =
            PsGetProcessInheritedFromUniqueProcessId(process);
        /* Parent zero may root only a process whose kernel parent is zero. */
        if (inheritedParentProcessId != NULL) {
            return HawkRememberAmbiguousOrphanProcess(
                processId,
                process,
                imageFileName
            );
        }
        HawkProcessLineageSeed seed;
        RtlZeroMemory(&seed, sizeof(seed));
        if (!HawkBuildProcessIdentity(
                processId,
                process,
                imageFileName,
                seed.actualBinaryHash,
                seed.processInstanceHash
            )) {
            return FALSE;
        }
        seed.governedLineage = directlyGoverned;
        /* Exact governed binaries can authoritatively root their own family. */
        seed.lineageAuthoritative = seed.governedLineage;
        RtlCopyMemory(
            seed.policyBinaryHash,
            seed.actualBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            seed.familyRootInstanceHash,
            seed.processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        const BOOLEAN stored = HawkRememberProcessIdentity(
            processId,
            process,
            imageFileName,
            &seed
        );
        RtlSecureZeroMemory(&seed, sizeof(seed));
        return stored;
    }
    if (!lineageSourceAuthoritative &&
        PsGetProcessInheritedFromUniqueProcessId(process) != parentProcessId) {
        return FALSE;
    }
    UCHAR parentActualBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR parentPolicyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR parentProcessInstanceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR parentFamilyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN parentGovernedLineage = FALSE;
    BOOLEAN parentLineageAuthoritative = FALSE;
    if (!HawkLookupProcessIdentity(
            parentProcessId,
            parentActualBinaryHash,
            parentPolicyBinaryHash,
            parentProcessInstanceHash,
            parentFamilyRootInstanceHash,
            &parentGovernedLineage,
            &parentLineageAuthoritative
        )) {
        return HawkRememberAmbiguousOrphanProcess(
            processId,
            process,
            imageFileName
        );
    }
    HawkProcessLineageSeed seed;
    RtlZeroMemory(&seed, sizeof(seed));
    if (!HawkBuildProcessIdentity(
            processId,
            process,
            imageFileName,
            seed.actualBinaryHash,
            seed.processInstanceHash
        )) {
        return FALSE;
    }
    const BOOLEAN directlyGoverned = HawkImageIsGoverned(imageFileName);
    const BOOLEAN parentLineageAmbiguous =
        parentGovernedLineage && !parentLineageAuthoritative;
    if (parentLineageAmbiguous) {
        /*
         * Ambiguity is transitive for a restart snapshot. Self-root every
         * surviving descendant as governed/non-authoritative so stale
         * inherited authority cannot abort seeding or silently survive a
         * material policy change. A protected create callback may later
         * replace this conservative identity with exact lineage.
         */
        seed.governedLineage = TRUE;
        seed.lineageAuthoritative = FALSE;
        seed.allowConservativeAuthorityDowngrade = TRUE;
        RtlCopyMemory(
            seed.policyBinaryHash,
            seed.actualBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            seed.familyRootInstanceHash,
            seed.processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
    } else {
        if (HawkCrossGovernedFamilyConflict(
                parentGovernedLineage,
                parentPolicyBinaryHash,
                directlyGoverned,
                seed.actualBinaryHash
            )) {
            RtlSecureZeroMemory(&seed, sizeof(seed));
            return FALSE;
        }
        seed.governedLineage = parentGovernedLineage || directlyGoverned;
        seed.lineageAuthoritative = directlyGoverned ||
            (lineageSourceAuthoritative && parentLineageAuthoritative);
        if (parentGovernedLineage) {
            RtlCopyMemory(
                seed.policyBinaryHash,
                parentPolicyBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                seed.familyRootInstanceHash,
                parentFamilyRootInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
        } else {
            RtlCopyMemory(
                seed.policyBinaryHash,
                seed.actualBinaryHash,
                HAWK_FLOOR_HASH_BYTES
            );
            RtlCopyMemory(
                seed.familyRootInstanceHash,
                seed.processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            );
        }
    }
    const BOOLEAN stored = HawkRememberProcessIdentity(
        processId,
        process,
        imageFileName,
        &seed
    );
    RtlSecureZeroMemory(&seed, sizeof(seed));
    RtlSecureZeroMemory(
        parentActualBinaryHash,
        sizeof(parentActualBinaryHash)
    );
    RtlSecureZeroMemory(
        parentPolicyBinaryHash,
        sizeof(parentPolicyBinaryHash)
    );
    RtlSecureZeroMemory(
        parentProcessInstanceHash,
        sizeof(parentProcessInstanceHash)
    );
    RtlSecureZeroMemory(
        parentFamilyRootInstanceHash,
        sizeof(parentFamilyRootInstanceHash)
    );
    return stored;
}

static NTSTATUS HawkSeedProcessIdentitiesUnarmed(
    const HawkWindowsProcessSeedEntry *processes,
    ULONG processCount
) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || processes == NULL || processCount == 0 ||
        processCount > HAWK_WINDOWS_MAX_PROCESS_SEED_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    InterlockedExchange(&gHawkIdentityCoverageReady, 0);
    InterlockedExchange64(&gHawkIdentityFailureCount, 0);
    for (ULONG index = 0; index < processCount; ++index) {
        if (processes[index].processId == 0 ||
            processes[index].processId == processes[index].parentProcessId) {
            return STATUS_INVALID_PARAMETER;
        }
        const HANDLE processId =
            (HANDLE)(ULONG_PTR)processes[index].processId;
        const HANDLE parentProcessId =
            (HANDLE)(ULONG_PTR)processes[index].parentProcessId;
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
        if (status == STATUS_INVALID_CID) {
            continue; /* process exited after the trusted service snapshot */
        }
        if (!NT_SUCCESS(status)) return status;
        PUNICODE_STRING imageFileName = NULL;
        status = SeLocateProcessImageName(process, &imageFileName);
        if (!NT_SUCCESS(status) || imageFileName == NULL) {
            if (imageFileName != NULL) ExFreePool(imageFileName);
            ObDereferenceObject(process);
            return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        }
        const BOOLEAN stored = HawkRestoreSeededProcessLineage(
            processId,
            parentProcessId,
            process,
            imageFileName,
            FALSE
        );
        ExFreePool(imageFileName);
        ObDereferenceObject(process);
        if (!stored) return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * This IOCTL is writable only by the Hawk service SID. Its complete
     * authenticated service snapshot establishes that each enumerated live
     * process has a PID/start-key/binary-bound table entry. PPID
     * reconstruction is observational and therefore never makes inherited
     * family lineage authoritative. Ambiguous governed lineage continues to
     * fail closed until a protected create callback or exact governed binary
     * supplies authority.
     */
    InterlockedExchange(&gHawkIdentityCoverageReady, 1);
    return STATUS_SUCCESS;
}

NTSTATUS HawkSeedProcessIdentities(
    const HawkWindowsProcessSeedEntry *processes,
    ULONG processCount
) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    HawkAcquireControlTransitionLock();
    /*
     * A verified hot policy replacement deliberately leaves enforcement
     * armed but marks identity coverage unavailable. During that bounded
     * state file/network callbacks fail closed, and process callbacks wait on
     * this transition lock. Permit one authenticated full snapshot to rebuild
     * identity authority; never permit an armed refresh over healthy coverage.
     */
    if (HawkPolicyIsArmed() && HawkIdentityCoverageReady()) {
        HawkReleaseControlTransitionLock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    const NTSTATUS status = HawkSeedProcessIdentitiesUnarmed(
        processes,
        processCount
    );
    HawkReleaseControlTransitionLock();
    return status;
}

VOID HawkForgetProcessIdentity(HANDLE processId) {
    if (gHawkProcesses == NULL || processId == NULL) return;
    const ULONG initial = HawkProcessSlot(processId);
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkProcessLock, &oldIrql);
    for (ULONG probe = 0; probe < HAWK_PROCESS_PROBES; ++probe) {
        HawkProcessIdentityEntry *entry = &gHawkProcesses[(initial + probe) & (HAWK_PROCESS_TABLE_SIZE - 1U)];
        if (entry->occupied && entry->processId == processId) {
            RtlSecureZeroMemory(entry, sizeof(*entry));
            break;
        }
    }
    KeReleaseSpinLock(&gHawkProcessLock, oldIrql);
}

static BOOLEAN HawkBinaryGoverned(
    const HawkFloorPolicySnapshot *snapshot,
    HawkFloorPrimitive primitive,
    const UCHAR binaryHash[HAWK_FLOOR_HASH_BYTES]
) {
    for (ULONG index = 0; index < snapshot->ruleCount; ++index) {
        const HawkFloorRule *rule = &snapshot->rules[index];
        if (rule->bindBinaryIdentity &&
            (rule->primitiveMask & (1ULL << (UINT32)primitive)) != 0 &&
            HawkBytesEqual(rule->binaryIdentityHash, binaryHash, HAWK_FLOOR_HASH_BYTES)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN HawkLineageRequiresFailClosed(
    const UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    BOOLEAN governedLineage,
    BOOLEAN lineageAuthoritative
) {
    return !lineageAuthoritative &&
        (governedLineage || HawkPolicyHashIsGoverned(policyBinaryHash));
}

BOOLEAN HawkImageIsGoverned(
    PCUNICODE_STRING imageFileName
) {
    if (imageFileName == NULL ||
        imageFileName->Buffer == NULL || imageFileName->Length == 0) return FALSE;
    UCHAR hash[HAWK_FLOOR_HASH_BYTES];
    HawkSha256UnicodeInsensitive(imageFileName, hash);
    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    BOOLEAN governed = FALSE;
    if (policy != NULL) {
        for (ULONG index = 0; index < policy->snapshot.ruleCount; ++index) {
            const HawkFloorRule *rule = &policy->snapshot.rules[index];
            if (rule->bindBinaryIdentity &&
                HawkBytesEqual(
                    rule->binaryIdentityHash,
                    hash,
                    HAWK_FLOOR_HASH_BYTES
                )) {
                governed = TRUE;
                break;
            }
        }
    }
    HawkReleasePolicy(policy);
    RtlSecureZeroMemory(hash, sizeof(hash));
    return governed;
}

static VOID HawkFinalizeCanonicalAction(HawkFloorRequest *request) {
    struct {
        UCHAR domain[32];
        UINT32 primitive;
        UINT32 reserved;
        UINT64 requestedRights;
        UINT64 policyEpoch;
        UCHAR tenantHash[HAWK_FLOOR_HASH_BYTES];
        UCHAR deviceHash[HAWK_FLOOR_HASH_BYTES];
        UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES];
        UCHAR stableResourceIdentityHash[HAWK_FLOOR_HASH_BYTES];
        UCHAR destinationReferenceHash[HAWK_FLOOR_HASH_BYTES];
    } material;
    C_ASSERT(sizeof("hawk.windows.floor-action.v1") <=
        sizeof(material.domain));
    RtlZeroMemory(&material, sizeof(material));
    RtlCopyMemory(
        material.domain,
        "hawk.windows.floor-action.v1",
        sizeof("hawk.windows.floor-action.v1")
    );
    material.primitive = (UINT32)request->primitive;
    material.requestedRights = request->requestedRights;
    material.policyEpoch = request->policyEpoch;
    RtlCopyMemory(material.tenantHash, request->tenantHash, HAWK_FLOOR_HASH_BYTES);
    RtlCopyMemory(material.deviceHash, request->deviceHash, HAWK_FLOOR_HASH_BYTES);
    RtlCopyMemory(
        material.processInstanceHash,
        request->processInstanceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        material.stableResourceIdentityHash,
        request->stableResourceIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        material.destinationReferenceHash,
        request->destinationReferenceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    HawkSha256Bytes(
        (const UCHAR *)&material,
        sizeof(material),
        request->canonicalActionHash
    );
    RtlSecureZeroMemory(&material, sizeof(material));
}

static HawkFloorPermit *HawkApplyMatchingPermit(
    HawkFloorRequest *request,
    const HawkPolicyAllocation *policy,
    HawkPermitAllocation *permits,
    UINT64 observedNow
) {
    request->permitPresent = false;
    RtlZeroMemory(request->permitDigest, HAWK_FLOOR_HASH_BYTES);
    if (permits == NULL || policy == NULL ||
        permits->policyGeneration != policy->generation ||
        permits->policySequence != policy->policySequence ||
        permits->armSessionEpoch !=
            (UINT64)InterlockedCompareExchange64(
                &gHawkArmSessionEpoch,
                0,
                0
            ) ||
        !HawkBytesEqual(
            permits->driverSessionId,
            gHawkDriverSessionId,
            sizeof(gHawkDriverSessionId)
        ) ||
        !HawkBytesEqual(
            permits->policyFingerprint,
            policy->policyFingerprint,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        !HawkBytesEqual(
            permits->tenantHash,
            policy->snapshot.tenantHash,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        !HawkBytesEqual(
            permits->deviceHash,
            policy->snapshot.deviceHash,
            HAWK_FLOOR_HASH_BYTES
        )) {
        return NULL;
    }
    HawkFloorPermit *permit = HawkFindIndexedPermit(
        permits,
        request->canonicalActionHash
    );
    if (permit == NULL || !permit->integrityVerified ||
        permit->primitive != request->primitive ||
        permit->requestedRights != request->requestedRights ||
        permit->policyEpoch != request->policyEpoch ||
        permit->expiresAtMonotonicNs <= observedNow ||
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
        )) {
        return NULL;
    }
    RtlCopyMemory(
        request->permitDigest,
        permit->permitDigest,
        HAWK_FLOOR_HASH_BYTES
    );
    request->permitPresent = true;
    return permit;
}

static HawkKernelDecision HawkEvaluateRequestWithPolicy(
    HawkFloorRequest *request,
    BOOLEAN permitBindingComplete,
    HawkPolicyAllocation *policy
) {
    const UINT64 observedNow = HawkMonotonicNanoseconds();
    if (policy->snapshot.expiresAtMonotonicNs <= observedNow) {
        const BOOLEAN expiredGoverned = HawkBinaryGoverned(
            &policy->snapshot,
            request->primitive,
            request->binaryIdentityHash
        );
        if (expiredGoverned) {
            InterlockedIncrement64(&gHawkBlockCount);
            return HawkKernelBlock;
        }
        InterlockedIncrement64(&gHawkAllowCount);
        return HawkKernelAllow;
    }
    if (!HawkBinaryGoverned(&policy->snapshot, request->primitive, request->binaryIdentityHash)) {
        InterlockedIncrement64(&gHawkAllowCount);
        return HawkKernelAllow;
    }
    RtlCopyMemory(request->tenantHash, policy->snapshot.tenantHash, HAWK_FLOOR_HASH_BYTES);
    RtlCopyMemory(request->deviceHash, policy->snapshot.deviceHash, HAWK_FLOOR_HASH_BYTES);
    request->policyEpoch = policy->snapshot.policyEpoch;
    HawkFinalizeCanonicalAction(request);
    HawkFloorPolicySnapshot snapshot = policy->snapshot;
    const HawkFloorDecision preliminaryDecision = HawkFloorEvaluate(
        &snapshot,
        request,
        observedNow
    );
    HawkFloorDecision decision = preliminaryDecision;
    HawkPermitAllocation *permits = NULL;
    if (preliminaryDecision.action == HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT &&
        permitBindingComplete) {
        permits = HawkAcquirePermits();
        HawkFloorPermit *matchedPermit = HawkApplyMatchingPermit(
            request,
            policy,
            permits,
            observedNow
        );
        if (request->permitPresent && permits != NULL &&
            permits->policyGeneration == policy->generation &&
            permits->policySequence == policy->policySequence &&
            HawkBytesEqual(
                permits->policyFingerprint,
                policy->policyFingerprint,
                HAWK_FLOOR_HASH_BYTES
            )) {
            snapshot.permitCount = matchedPermit == NULL ? 0U : 1U;
            snapshot.permits = matchedPermit;
            decision = HawkFloorEvaluate(&snapshot, request, observedNow);
        }
    }
    if (request->permitPresent && !decision.permitConsumed) {
        InterlockedIncrement64(&gHawkPolicyRejectCount);
    }
    HawkReleasePermits(permits);
    if (decision.action == HAWK_FLOOR_ACTION_ALLOW) {
        InterlockedIncrement64(&gHawkAllowCount);
        return HawkKernelAllow;
    }
    InterlockedIncrement64(&gHawkBlockCount);
    return decision.action == HAWK_FLOOR_ACTION_BLOCK
        ? HawkKernelBlock : HawkKernelLocalEscalationRequired;
}

static HawkKernelDecision HawkEvaluateRequest(
    HawkFloorRequest *request,
    BOOLEAN permitBindingComplete
) {
    if (!HawkPolicyIsArmed()) return HawkKernelAllow;
    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    if (policy == NULL) {
        InterlockedIncrement64(&gHawkPolicyRejectCount);
        return HawkKernelBlock;
    }
    const HawkKernelDecision decision = HawkEvaluateRequestWithPolicy(
        request,
        permitBindingComplete,
        policy
    );
    HawkReleasePolicy(policy);
    return decision;
}

NTSTATUS HawkInitializeKernelPolicy(VOID) {
    if (InterlockedCompareExchange(&gHawkPolicyInitialized, 1, 0) != 0) return STATUS_SUCCESS;
    KeInitializeSpinLock(&gHawkPolicyLock);
    KeInitializeSpinLock(&gHawkProcessLock);
    KeInitializeSpinLock(&gHawkPermitLock);
    ExInitializePushLock(&gHawkControlTransitionLock);
    KeInitializeEvent(&gHawkDeferredReleaseEvent, NotificationEvent, TRUE);
    KeInitializeTimer(&gHawkPolicyExpiryTimer);
    KeInitializeDpc(
        &gHawkPolicyExpiryDpc,
        HawkPolicyExpiryDpc,
        NULL
    );
    KeInitializeEvent(&gHawkPolicyExpiryIdleEvent, NotificationEvent, TRUE);
    ExInitializeRundownProtection(&gHawkPolicyExpiryRundown);
    InterlockedExchange(&gHawkDeferredReleaseCount, 0);
    InterlockedExchange(&gHawkPolicyExpiryWorkQueued, 0);
    InterlockedExchange(&gHawkPolicyExpiryWorkPending, 0);
    InterlockedExchange(&gHawkPolicyExpiryStopping, 0);
    InterlockedExchange64(&gHawkArmSessionEpoch, 0);
    UUID driverSessionId;
    C_ASSERT(sizeof(driverSessionId) == sizeof(gHawkDriverSessionId));
    const NTSTATUS sessionStatus = ExUuidCreate(&driverSessionId);
    if (!NT_SUCCESS(sessionStatus)) {
        InterlockedExchange(&gHawkPolicyInitialized, 0);
        return sessionStatus;
    }
    RtlCopyMemory(
        gHawkDriverSessionId,
        &driverSessionId,
        sizeof(gHawkDriverSessionId)
    );
    RtlSecureZeroMemory(&driverSessionId, sizeof(driverSessionId));
    if (HawkBytesAllZero(
            gHawkDriverSessionId,
            sizeof(gHawkDriverSessionId)
        )) {
        InterlockedExchange(&gHawkPolicyInitialized, 0);
        return STATUS_UNSUCCESSFUL;
    }
    gHawkProcesses = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HawkProcessIdentityEntry) * HAWK_PROCESS_TABLE_SIZE,
        HAWK_POLICY_POOL_TAG
    );
    if (gHawkProcesses == NULL) {
        InterlockedExchange(&gHawkPolicyInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(gHawkProcesses, sizeof(HawkProcessIdentityEntry) * HAWK_PROCESS_TABLE_SIZE);
    InterlockedExchange(&gHawkIdentityCoverageReady, 0);
    InterlockedExchange64(&gHawkIdentityFailureCount, 0);
    return STATUS_SUCCESS;
}

VOID HawkShutdownKernelPolicy(VOID) {
    InterlockedExchange(&gHawkPolicyArmed, 0);
    InterlockedExchange(&gHawkIdentityCoverageReady, 0);
    InterlockedExchange(&gHawkPolicyExpiryStopping, 1);
    (VOID)KeCancelTimer(&gHawkPolicyExpiryTimer);
    (VOID)KeRemoveQueueDpc(&gHawkPolicyExpiryDpc);
    /*
     * KeRemoveQueueDpc does not wait for an already-running DPC. Driver
     * teardown is rare and must prove no DPC can enqueue this image's work
     * item after the queue-state sample below.
     */
    KeFlushQueuedDpcs();
    ExWaitForRundownProtectionRelease(&gHawkPolicyExpiryRundown);
    HawkClearPermits();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPolicyLock, &oldIrql);
    HawkPolicyAllocation *old = gHawkPolicy;
    gHawkPolicy = NULL;
    KeReleaseSpinLock(&gHawkPolicyLock, oldIrql);
    HawkReleasePolicy(old);
    if (gHawkProcesses != NULL) {
        RtlSecureZeroMemory(gHawkProcesses, sizeof(HawkProcessIdentityEntry) * HAWK_PROCESS_TABLE_SIZE);
        ExFreePoolWithTag(gHawkProcesses, HAWK_POLICY_POOL_TAG);
        gHawkProcesses = NULL;
    }
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        (VOID)KeWaitForSingleObject(
            &gHawkDeferredReleaseEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    }
    InterlockedExchange(&gHawkPolicyInitialized, 0);
    InterlockedExchange64(&gHawkArmSessionEpoch, 0);
    RtlSecureZeroMemory(gHawkDriverSessionId, sizeof(gHawkDriverSessionId));
}

NTSTATUS HawkFloorPublishSnapshot(const VOID *input, ULONG inputBytes) {
    const ULONG headerBytes = FIELD_OFFSET(HawkWindowsPolicyEnvelope, rules);
    if (input == NULL || inputBytes < headerBytes || inputBytes > HAWK_WINDOWS_MAX_POLICY_BYTES) {
        return HawkRejectPolicy(STATUS_INVALID_BUFFER_SIZE);
    }
    const HawkWindowsPolicyEnvelope *envelope = input;
    if (envelope->magic != HAWK_WINDOWS_POLICY_MAGIC ||
        envelope->version != HAWK_WINDOWS_POLICY_VERSION ||
        envelope->totalSize != inputBytes ||
        envelope->ruleCount > HAWK_FLOOR_MAX_RULES ||
        inputBytes != headerBytes + envelope->ruleCount * sizeof(HawkFloorRule) ||
        envelope->signatureVerified != 1 ||
        envelope->configurationIntegrityValid != 1 ||
        envelope->generation == 0 ||
        envelope->policySequence == 0 ||
        HawkBytesAllZero(envelope->policyFingerprint, HAWK_FLOOR_HASH_BYTES) ||
        !HawkBytesAllZero(envelope->reserved, sizeof(envelope->reserved)) ||
        envelope->validForNanoseconds == 0 ||
        envelope->validForNanoseconds > HAWK_MAX_POLICY_LIFETIME_NS ||
        envelope->policyVersion[HAWK_FLOOR_REFERENCE_BYTES - 1] != '\0') {
        return HawkRejectPolicy(STATUS_INVALID_PARAMETER);
    }
    for (ULONG primitive = 0; primitive < HAWK_FLOOR_PRIMITIVE_COUNT; ++primitive) {
        if (envelope->defaultActionByPrimitive[primitive] != HAWK_FLOOR_ACTION_ALLOW) {
            return HawkRejectPolicy(STATUS_ACCESS_DENIED);
        }
    }
    for (ULONG index = 0; index < envelope->ruleCount; ++index) {
        const HawkFloorRule *rule = &envelope->rules[index];
        if (rule->action < HAWK_FLOOR_ACTION_ALLOW ||
            rule->action > HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT ||
            (rule->action != HAWK_FLOOR_ACTION_ALLOW && !rule->bindBinaryIdentity) ||
            rule->ruleReference[HAWK_FLOOR_REFERENCE_BYTES - 1] != '\0') {
            return HawkRejectPolicy(STATUS_ACCESS_DENIED);
        }
    }
    const SIZE_T allocationBytes = FIELD_OFFSET(HawkPolicyAllocation, rules) +
        (SIZE_T)envelope->ruleCount * sizeof(HawkFloorRule);
    HawkPolicyAllocation *replacement = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        allocationBytes,
        HAWK_POLICY_POOL_TAG
    );
    if (replacement == NULL) return HawkRejectPolicy(STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(replacement, allocationBytes);
    replacement->references = 1;
    replacement->allocationBytes = allocationBytes;
    replacement->generation = envelope->generation;
    replacement->policySequence = envelope->policySequence;
    RtlCopyMemory(
        replacement->policyFingerprint,
        envelope->policyFingerprint,
        HAWK_FLOOR_HASH_BYTES
    );
    replacement->snapshot.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    replacement->snapshot.signatureVerified = true;
    replacement->snapshot.configurationIntegrityValid = true;
    replacement->snapshot.policyEpoch = envelope->policySequence;
    const UINT64 observedNow = HawkMonotonicNanoseconds();
    if (envelope->validForNanoseconds > (~0ULL - observedNow)) {
        HawkReleasePolicy(replacement);
        return HawkRejectPolicy(STATUS_INTEGER_OVERFLOW);
    }
    replacement->snapshot.expiresAtMonotonicNs =
        observedNow + envelope->validForNanoseconds;
    replacement->snapshot.ruleCount = envelope->ruleCount;
    replacement->snapshot.rules = replacement->rules;
    replacement->snapshot.permitCount = 0;
    replacement->snapshot.permits = NULL;
    RtlCopyMemory(replacement->snapshot.tenantHash, envelope->tenantHash, HAWK_FLOOR_HASH_BYTES);
    RtlCopyMemory(replacement->snapshot.deviceHash, envelope->deviceHash, HAWK_FLOOR_HASH_BYTES);
    RtlCopyMemory(replacement->snapshot.policyVersion, envelope->policyVersion, HAWK_FLOOR_REFERENCE_BYTES);
    RtlCopyMemory(replacement->snapshot.defaultActionByPrimitive,
        envelope->defaultActionByPrimitive, sizeof(envelope->defaultActionByPrimitive));
    if (envelope->ruleCount > 0) {
        RtlCopyMemory(replacement->rules, envelope->rules,
            envelope->ruleCount * sizeof(HawkFloorRule));
    }
    BOOLEAN replacementNeedsNetwork = FALSE;
    for (ULONG index = 0; index < envelope->ruleCount; ++index) {
        if ((envelope->rules[index].primitiveMask &
            (1ULL << (UINT32)HAWK_FLOOR_NETWORK_CONNECT)) != 0) {
            replacementNeedsNetwork = TRUE;
            break;
        }
    }
    HawkAcquireControlTransitionLock();
    KIRQL oldIrql;
    KeAcquireSpinLock(&gHawkPolicyLock, &oldIrql);
    HawkPolicyAllocation *old = gHawkPolicy;
    if (old != NULL && replacement->generation <= old->generation) {
        KeReleaseSpinLock(&gHawkPolicyLock, oldIrql);
        HawkReleaseControlTransitionLock();
        HawkReleasePolicy(replacement);
        return HawkRejectPolicy(STATUS_REVISION_MISMATCH);
    }
    KeReleaseSpinLock(&gHawkPolicyLock, oldIrql);

    BOOLEAN oldNeedsNetwork = FALSE;
    if (old != NULL) {
        for (ULONG index = 0; index < old->snapshot.ruleCount; ++index) {
            if ((old->rules[index].primitiveMask &
                (1ULL << (UINT32)HAWK_FLOOR_NETWORK_CONNECT)) != 0) {
                oldNeedsNetwork = TRUE;
                break;
            }
        }
    }
    const BOOLEAN wasArmed = HawkPolicyIsArmed();
    const BOOLEAN priorIdentityCoverage = HawkIdentityCoverageReady();
    if (wasArmed && !priorIdentityCoverage) {
        HawkReleaseControlTransitionLock();
        HawkReleasePolicy(replacement);
        return HawkRejectPolicy(STATUS_INVALID_DEVICE_STATE);
    }

    /*
     * No callback may treat old lineage as current under a new governed-binary
     * set. File/network callbacks fail closed while the protected service
     * submits a complete replacement identity snapshot; process callbacks are
     * serialized by this transition lock.
     */
    const BOOLEAN networkTransitionRequired =
        wasArmed && (oldNeedsNetwork || replacementNeedsNetwork);
    if (networkTransitionRequired && !HawkWfpReady()) {
        /*
         * A red WFP state must remain repairable. This first bank transition
         * repairs the control point only; it cannot authorize the replacement
         * policy because that policy and its new epoch are not installed yet.
         */
        const NTSTATUS repairStatus = HawkWfpReauthorizeFlows();
        if (!NT_SUCCESS(repairStatus)) {
            HawkReleaseControlTransitionLock();
            HawkReleasePolicy(replacement);
            return HawkRejectPolicy(repairStatus);
        }
    }

    InterlockedExchange(&gHawkIdentityCoverageReady, 0);
    KeAcquireSpinLock(&gHawkPolicyLock, &oldIrql);
    gHawkPolicy = replacement;
    KeReleaseSpinLock(&gHawkPolicyLock, oldIrql);
    /* Preserve the floor while invalidating every old policy/permit epoch. */
    (VOID)HawkInvalidateArmAuthorityPreserveEnforcement();
    NTSTATUS postPublishReauthorizationStatus = STATUS_SUCCESS;
    if (networkTransitionRequired) {
        /*
         * This post-publish transition is authoritative. It forces every
         * surviving ALE flow to re-enter evaluation only after the new policy
         * and epoch are visible. A failed transition cannot leave the device
         * armed under ambiguous flow authority.
         */
        postPublishReauthorizationStatus = HawkWfpReauthorizeFlows();
        if (!NT_SUCCESS(postPublishReauthorizationStatus)) {
            (VOID)HawkAdvanceArmSessionEpoch();
        }
    }
    const UINT64 scheduleNow = HawkMonotonicNanoseconds();
    const UINT64 remainingUntilExpiry =
        replacement->snapshot.expiresAtMonotonicNs > scheduleNow
            ? replacement->snapshot.expiresAtMonotonicNs - scheduleNow
            : 1ULL;
    HawkSchedulePolicyExpiry(remainingUntilExpiry);
    HawkReleaseControlTransitionLock();
    HawkReleasePolicy(old);
    return postPublishReauthorizationStatus;
}

typedef enum HawkPermitInstallResult {
    HawkPermitInstallRejected = 0,
    HawkPermitInstallReplaced = 1
} HawkPermitInstallResult;

static HawkPermitInstallResult HawkInstallPermitsIfPolicyCurrent(
    const HawkPolicyAllocation *policy,
    HawkPermitAllocation *replacement
) {
    HawkPermitInstallResult result = HawkPermitInstallRejected;
    HawkPermitAllocation *old = NULL;

    /*
     * A publish is an exact active-set replacement, not an append. Replay
     * history lives in a separate bounded Bloom projection until material
     * policy replacement. This keeps callback lookup and publish latency
     * independent of expired tombstones. Bloom false positives fail closed;
     * they can deny a fresh permit but can never revive an old one.
     */
    HawkAcquireControlTransitionLock();
    if (gHawkPolicy == policy && HawkPolicyIsArmed() &&
        replacement->armSessionEpoch ==
            (UINT64)InterlockedCompareExchange64(
                &gHawkArmSessionEpoch,
                0,
                0
            ) &&
        HawkBytesEqual(
            replacement->driverSessionId,
            gHawkDriverSessionId,
            sizeof(gHawkDriverSessionId)
        ) && gHawkPermitReplayDigestCount <=
            HAWK_PERMIT_REPLAY_MAX_DIGESTS - replacement->permitCount) {
        BOOLEAN replay = FALSE;
        for (ULONG index = 0; index < replacement->permitCount; ++index) {
            if (HawkPermitReplaySeen(
                    replacement->permits[index].permitDigest
                )) {
                replay = TRUE;
                break;
            }
        }
        KIRQL oldIrql;
        KeAcquireSpinLock(&gHawkPermitLock, &oldIrql);
        HawkPermitAllocation *current = gHawkPermits;
        if (!replay && (current == NULL ||
            (current->policyGeneration == replacement->policyGeneration &&
             current->policySequence == replacement->policySequence &&
             current->armSessionEpoch == replacement->armSessionEpoch &&
             HawkBytesEqual(
                 current->driverSessionId,
                 replacement->driverSessionId,
                 sizeof(current->driverSessionId)
             ) &&
             HawkBytesEqual(
                 current->policyFingerprint,
                 replacement->policyFingerprint,
                 HAWK_FLOOR_HASH_BYTES
             ) &&
             replacement->permitBatchSequence >
                 current->permitBatchSequence))) {
            old = current;
            gHawkPermits = replacement;
            result = HawkPermitInstallReplaced;
        }
        KeReleaseSpinLock(&gHawkPermitLock, oldIrql);
        if (result == HawkPermitInstallReplaced) {
            for (ULONG index = 0; index < replacement->permitCount; ++index) {
                HawkRememberPermitReplayDigest(
                    replacement->permits[index].permitDigest
                );
            }
        }
    }
    HawkReleaseControlTransitionLock();
    HawkReleasePermits(old);
    return result;
}

NTSTATUS HawkFloorPublishPermits(const VOID *input, ULONG inputBytes) {
    const ULONG headerBytes = FIELD_OFFSET(HawkWindowsPermitEnvelope, permits);
    if (input == NULL || inputBytes < headerBytes ||
        inputBytes > HAWK_WINDOWS_MAX_PERMIT_BYTES) {
        return HawkRejectPolicy(STATUS_INVALID_BUFFER_SIZE);
    }
    const HawkWindowsPermitEnvelope *envelope = input;
    if (envelope->magic != HAWK_WINDOWS_PERMIT_MAGIC ||
        envelope->version != HAWK_WINDOWS_PERMIT_VERSION ||
        envelope->totalSize != inputBytes ||
        envelope->permitCount > HAWK_FLOOR_MAX_PERMITS ||
        inputBytes != headerBytes +
            envelope->permitCount * sizeof(HawkWindowsPermitEntry) ||
        envelope->policyGeneration == 0 ||
        envelope->policySequence == 0 ||
        envelope->permitBatchSequence == 0 ||
        envelope->armSessionEpoch == 0 ||
        HawkBytesAllZero(
            envelope->driverSessionId,
            sizeof(envelope->driverSessionId)
        ) ||
        envelope->brokerAuthenticated != 1 ||
        envelope->configurationIntegrityValid != 1 ||
        !HawkBytesAllZero(envelope->reserved, sizeof(envelope->reserved)) ||
        HawkBytesAllZero(envelope->policyFingerprint, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(envelope->tenantHash, HAWK_FLOOR_HASH_BYTES) ||
        HawkBytesAllZero(envelope->deviceHash, HAWK_FLOOR_HASH_BYTES)) {
        return HawkRejectPolicy(STATUS_INVALID_PARAMETER);
    }

    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    if (policy == NULL || policy->generation != envelope->policyGeneration ||
        policy->policySequence != envelope->policySequence ||
        !HawkBytesEqual(
            policy->policyFingerprint,
            envelope->policyFingerprint,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        !HawkBytesEqual(
            policy->snapshot.tenantHash,
            envelope->tenantHash,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        !HawkBytesEqual(
            policy->snapshot.deviceHash,
            envelope->deviceHash,
            HAWK_FLOOR_HASH_BYTES
        ) ||
        policy->snapshot.expiresAtMonotonicNs <= HawkMonotonicNanoseconds()) {
        HawkReleasePolicy(policy);
        return HawkRejectPolicy(STATUS_REVISION_MISMATCH);
    }

    /* Active permits are compact; replay history is stored separately. */
    const SIZE_T allocationBytes = FIELD_OFFSET(HawkPermitAllocation, permits) +
        (SIZE_T)envelope->permitCount * sizeof(HawkFloorPermit);
    HawkPermitAllocation *replacement = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        allocationBytes,
        HAWK_POLICY_POOL_TAG
    );
    if (replacement == NULL) {
        HawkReleasePolicy(policy);
        return HawkRejectPolicy(STATUS_INSUFFICIENT_RESOURCES);
    }
    RtlZeroMemory(replacement, allocationBytes);
    replacement->references = 1;
    replacement->allocationBytes = allocationBytes;
    replacement->policyGeneration = envelope->policyGeneration;
    replacement->policySequence = envelope->policySequence;
    replacement->permitBatchSequence = envelope->permitBatchSequence;
    replacement->armSessionEpoch = envelope->armSessionEpoch;
    replacement->permitCount = envelope->permitCount;
    RtlCopyMemory(
        replacement->policyFingerprint,
        envelope->policyFingerprint,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        replacement->tenantHash,
        envelope->tenantHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        replacement->deviceHash,
        envelope->deviceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        replacement->driverSessionId,
        envelope->driverSessionId,
        sizeof(replacement->driverSessionId)
    );
    const UINT64 observedNow = HawkMonotonicNanoseconds();
    for (ULONG index = 0; index < envelope->permitCount; ++index) {
        const HawkWindowsPermitEntry *wire = &envelope->permits[index];
        if (wire->integrityVerified != 1 ||
            !HawkBytesAllZero(wire->reserved0, sizeof(wire->reserved0)) ||
            !HawkBytesAllZero(wire->reserved1, sizeof(wire->reserved1)) ||
            !HawkPrimitiveValid((HawkFloorPrimitive)wire->primitive) ||
            !HawkPrimitivePermitBindingImplemented(
                (HawkFloorPrimitive)wire->primitive
            ) ||
            wire->requestedRights == 0 ||
            wire->validForNanoseconds == 0 ||
            wire->validForNanoseconds > HAWK_MAX_PERMIT_LIFETIME_NS ||
            wire->maximumUses == 0 || wire->maximumUses > 64 ||
            (index > 0 && !HawkBytesLexicographicLess(
                envelope->permits[index - 1U].permitDigest,
                wire->permitDigest,
                HAWK_FLOOR_HASH_BYTES
            )) ||
            HawkBytesAllZero(
                wire->processInstanceHash,
                HAWK_FLOOR_HASH_BYTES
            ) ||
            HawkBytesAllZero(wire->canonicalActionHash, HAWK_FLOOR_HASH_BYTES) ||
            HawkBytesAllZero(wire->permitDigest, HAWK_FLOOR_HASH_BYTES) ||
            (HawkPrimitiveNeedsStableResource((HawkFloorPrimitive)wire->primitive) &&
                HawkBytesAllZero(
                    wire->stableResourceIdentityHash,
                    HAWK_FLOOR_HASH_BYTES
                )) ||
            (HawkPrimitiveNeedsDestination((HawkFloorPrimitive)wire->primitive) &&
                HawkBytesAllZero(
                    wire->destinationReferenceHash,
                    HAWK_FLOOR_HASH_BYTES
                )) ||
            wire->validForNanoseconds > (~0ULL - observedNow)) {
            HawkReleasePermits(replacement);
            HawkReleasePolicy(policy);
            return HawkRejectPolicy(STATUS_INVALID_PARAMETER);
        }
        HawkFloorPermit *permit = &replacement->permits[index];
        permit->integrityVerified = true;
        permit->primitive = (HawkFloorPrimitive)wire->primitive;
        permit->requestedRights = wire->requestedRights;
        permit->policyEpoch = envelope->policySequence;
        permit->expiresAtMonotonicNs = observedNow + wire->validForNanoseconds;
        permit->maximumUses = wire->maximumUses;
        InterlockedExchange((volatile LONG *)&permit->consumedUses, 0);
        RtlCopyMemory(
            permit->processInstanceHash,
            wire->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            permit->stableResourceIdentityHash,
            wire->stableResourceIdentityHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            permit->destinationReferenceHash,
            wire->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            permit->canonicalActionHash,
            wire->canonicalActionHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            permit->permitDigest,
            wire->permitDigest,
            HAWK_FLOOR_HASH_BYTES
        );
    }

    if (!HawkBuildPermitIndex(replacement)) {
        HawkReleasePermits(replacement);
        HawkReleasePolicy(policy);
        return HawkRejectPolicy(STATUS_OBJECT_NAME_COLLISION);
    }

    const HawkPermitInstallResult installResult =
        HawkInstallPermitsIfPolicyCurrent(policy, replacement);
    if (installResult == HawkPermitInstallRejected) {
        HawkReleasePermits(replacement);
        HawkReleasePolicy(policy);
        return HawkRejectPolicy(STATUS_REVISION_MISMATCH);
    }
    HawkReleasePolicy(policy);
    return STATUS_SUCCESS;
}

NTSTATUS HawkSetPolicyArmed(BOOLEAN armed, UINT64 expectedGeneration) {
    HawkAcquireControlTransitionLock();
    if (!armed) {
        (VOID)HawkAdvanceArmSessionEpoch();
        HawkReleaseControlTransitionLock();
        return STATUS_SUCCESS;
    }
    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    BOOLEAN networkRequired = FALSE;
    if (policy != NULL) {
        for (ULONG index = 0; index < policy->snapshot.ruleCount; ++index) {
            if ((policy->rules[index].primitiveMask &
                (1ULL << (UINT32)HAWK_FLOOR_NETWORK_CONNECT)) != 0) {
                networkRequired = TRUE;
                break;
            }
        }
    }
    if (policy == NULL || policy->generation != expectedGeneration ||
        !HawkIdentityCoverageReady() ||
        policy->snapshot.expiresAtMonotonicNs <= HawkMonotonicNanoseconds()) {
        HawkReleasePolicy(policy);
        HawkReleaseControlTransitionLock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * A failed/unknown active bank must be repaired before any arm attempt.
     * This first transition is repair only; the mandatory second transition
     * below occurs after the new arm epoch is authoritative.
     */
    if (networkRequired && !HawkWfpReady() &&
        !NT_SUCCESS(HawkWfpReauthorizeFlows())) {
        HawkReleasePolicy(policy);
        HawkReleaseControlTransitionLock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    const UINT64 nextArmEpoch = HawkAdvanceArmSessionEpoch();
    if (!HawkCommitArmSession(nextArmEpoch)) {
        HawkReleasePolicy(policy);
        HawkReleaseControlTransitionLock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (networkRequired && !NT_SUCCESS(HawkWfpReauthorizeFlows())) {
        /*
         * Never retain armed authority if existing flows were not forced
         * through the newly committed arm epoch.
         */
        (VOID)HawkAdvanceArmSessionEpoch();
        HawkReleasePolicy(policy);
        HawkReleaseControlTransitionLock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    HawkReleasePolicy(policy);
    HawkReleaseControlTransitionLock();
    return STATUS_SUCCESS;
}

VOID HawkGetPolicyStatus(HawkWindowsPolicyStatus *status) {
    RtlZeroMemory(status, sizeof(*status));
    status->version = HAWK_WINDOWS_POLICY_VERSION;
    status->armed = InterlockedCompareExchange(&gHawkPolicyArmed, 0, 0) != 0;
    status->identityCoverageReady = HawkIdentityCoverageReady();
    status->wfpReady = HawkWfpReady();
    status->allowCount = (UINT64)InterlockedCompareExchange64(&gHawkAllowCount, 0, 0);
    status->blockCount = (UINT64)InterlockedCompareExchange64(&gHawkBlockCount, 0, 0);
    status->policyRejectCount = (UINT64)InterlockedCompareExchange64(&gHawkPolicyRejectCount, 0, 0);
    status->armSessionEpoch = (UINT64)InterlockedCompareExchange64(
        &gHawkArmSessionEpoch,
        0,
        0
    );
    RtlCopyMemory(
        status->driverSessionId,
        gHawkDriverSessionId,
        sizeof(status->driverSessionId)
    );
    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    if (policy != NULL) {
        status->policyLoaded = 1;
        status->generation = policy->generation;
        status->policySequence = policy->policySequence;
        RtlCopyMemory(
            status->policyFingerprint,
            policy->policyFingerprint,
            HAWK_FLOOR_HASH_BYTES
        );
        status->policyCurrent = policy->snapshot.expiresAtMonotonicNs > HawkMonotonicNanoseconds();
    }
    HawkPermitAllocation *permits = HawkAcquirePermits();
    if (permits != NULL && policy != NULL &&
        permits->policyGeneration == policy->generation &&
        permits->policySequence == policy->policySequence &&
        permits->armSessionEpoch == status->armSessionEpoch &&
        HawkBytesEqual(
            permits->driverSessionId,
            status->driverSessionId,
            sizeof(status->driverSessionId)
        )) {
        status->permitBatchSequence = (UINT64)InterlockedCompareExchange64(
            (volatile LONG64 *)&permits->permitBatchSequence,
            0,
            0
        );
    }
    HawkReleasePermits(permits);
    HawkReleasePolicy(policy);
}

static BOOLEAN HawkBindFileIdentity(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects,
    HawkFloorRequest *request,
    BOOLEAN *stableIdentityVerified
) {
    if (data == NULL || objects == NULL || request == NULL ||
        stableIdentityVerified == NULL || objects->FileObject == NULL ||
        objects->Volume == NULL || objects->Instance == NULL) {
        return FALSE;
    }
    *stableIdentityVerified = FALSE;
    if (objects->FileObject->FileName.Buffer == NULL ||
        objects->FileObject->FileName.Length == 0) {
        return FALSE;
    }
    HawkSha256UnicodeInsensitive(
        &objects->FileObject->FileName,
        request->resourceReferenceHash
    );
    if (HawkBytesAllZero(
            request->resourceReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        )) {
        return FALSE;
    }

    typedef struct HawkFileStableMaterial {
        UCHAR domain[40];
        UINT64 volumeCreationTime;
        UINT32 volumeSerialNumber;
        UINT32 reserved;
        UINT64 fileIndex;
    } HawkFileStableMaterial;
    C_ASSERT(sizeof(HawkFileStableMaterial) == 64U);

    FLT_FILESYSTEM_TYPE fileSystemType = FLT_FSTYPE_UNKNOWN;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
        !KeAreAllApcsDisabled() && IoGetTopLevelIrp() == NULL) {
        UCHAR volumeBuffer[512];
        IO_STATUS_BLOCK volumeIoStatus;
        FILE_INTERNAL_INFORMATION internalInformation;
        ULONG returnedBytes = 0;
        RtlZeroMemory(volumeBuffer, sizeof(volumeBuffer));
        RtlZeroMemory(&volumeIoStatus, sizeof(volumeIoStatus));
        RtlZeroMemory(&internalInformation, sizeof(internalInformation));
        const NTSTATUS fileSystemStatus = FltGetFileSystemType(
            objects->Instance,
            &fileSystemType
        );
        const NTSTATUS fileStatus = FltQueryInformationFile(
            objects->Instance,
            objects->FileObject,
            &internalInformation,
            sizeof(internalInformation),
            FileInternalInformation,
            &returnedBytes
        );
        NTSTATUS volumeStatus = STATUS_NOT_SUPPORTED;
        if (NT_SUCCESS(fileSystemStatus) &&
            (fileSystemType == FLT_FSTYPE_NTFS ||
                fileSystemType == FLT_FSTYPE_REFS) &&
            NT_SUCCESS(fileStatus) &&
            returnedBytes >= sizeof(internalInformation) &&
            internalInformation.IndexNumber.QuadPart != 0) {
            volumeStatus = FltQueryVolumeInformation(
                objects->Instance,
                &volumeIoStatus,
                volumeBuffer,
                sizeof(volumeBuffer),
                FileFsVolumeInformation
            );
        }
        const FILE_FS_VOLUME_INFORMATION *volumeInformation =
            (const FILE_FS_VOLUME_INFORMATION *)volumeBuffer;
        if (NT_SUCCESS(volumeStatus) &&
            volumeIoStatus.Information >=
                FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) &&
            volumeInformation->VolumeCreationTime.QuadPart > 0 &&
            volumeInformation->VolumeSerialNumber != 0 &&
            NT_SUCCESS(fileStatus) &&
            returnedBytes >= sizeof(internalInformation) &&
            internalInformation.IndexNumber.QuadPart != 0) {
            HawkFileStableMaterial material;
            RtlZeroMemory(&material, sizeof(material));
            RtlCopyMemory(
                material.domain,
                "hawk.windows.file-identity.v2",
                sizeof("hawk.windows.file-identity.v2")
            );
            material.volumeCreationTime =
                (UINT64)volumeInformation->VolumeCreationTime.QuadPart;
            material.volumeSerialNumber =
                volumeInformation->VolumeSerialNumber;
            material.fileIndex =
                (UINT64)internalInformation.IndexNumber.QuadPart;
            HawkSha256Bytes(
                (const UCHAR *)&material,
                sizeof(material),
                request->stableResourceIdentityHash
            );
            RtlSecureZeroMemory(&material, sizeof(material));
            *stableIdentityVerified = !HawkBytesAllZero(
                request->stableResourceIdentityHash,
                HAWK_FLOOR_HASH_BYTES
            );
        }
        RtlSecureZeroMemory(volumeBuffer, sizeof(volumeBuffer));
        RtlSecureZeroMemory(&internalInformation, sizeof(internalInformation));
    }
    if (!*stableIdentityVerified) {
        struct {
            UCHAR domain[40];
            UCHAR pathContextHash[HAWK_FLOOR_HASH_BYTES];
        } pathContext;
        RtlZeroMemory(&pathContext, sizeof(pathContext));
        RtlCopyMemory(
            pathContext.domain,
            "hawk.windows.file-path-context.v1",
            sizeof("hawk.windows.file-path-context.v1")
        );
        RtlCopyMemory(
            pathContext.pathContextHash,
            request->resourceReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        HawkSha256Bytes(
            (const UCHAR *)&pathContext,
            sizeof(pathContext),
            request->stableResourceIdentityHash
        );
        RtlSecureZeroMemory(&pathContext, sizeof(pathContext));
    }
    return !HawkBytesAllZero(
        request->stableResourceIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
}

static BOOLEAN HawkBindSetInformationDestination(
    PFLT_CALLBACK_DATA data,
    HawkFloorRequest *request
) {
    if (data == NULL || request == NULL ||
        data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) {
        return TRUE;
    }
    const FILE_INFORMATION_CLASS informationClass =
        data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (informationClass != FileRenameInformation &&
        informationClass != FileRenameInformationEx &&
        informationClass != FileLinkInformation &&
        informationClass != FileLinkInformationEx &&
        informationClass != FileShortNameInformation) {
        return TRUE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    const ULONG length = data->Iopb->Parameters.SetFileInformation.Length;
    const VOID *buffer = data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (buffer == NULL || length == 0 || length > 65536U) return FALSE;
    UCHAR bufferDigest[HAWK_FLOOR_HASH_BYTES];
    __try {
        /*
         * Filter Manager supplies SetFileInformation.InfoBuffer as a
         * system-space buffer. Probing it as a user pointer would reject
         * ordinary user-originated rename/link requests even though the
         * callback itself receives a kernel address.
         */
        HawkSha256Bytes((const UCHAR *)buffer, length, bufferDigest);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlSecureZeroMemory(bufferDigest, sizeof(bufferDigest));
        return FALSE;
    }
    struct {
        UCHAR domain[40];
        UINT32 informationClass;
        UINT32 length;
        UCHAR bufferDigest[HAWK_FLOOR_HASH_BYTES];
    } material;
    C_ASSERT(sizeof("hawk.windows.setinfo-destination.v1") <=
        sizeof(material.domain));
    RtlZeroMemory(&material, sizeof(material));
    RtlCopyMemory(
        material.domain,
        "hawk.windows.setinfo-destination.v1",
        sizeof("hawk.windows.setinfo-destination.v1")
    );
    material.informationClass = (UINT32)informationClass;
    material.length = length;
    RtlCopyMemory(
        material.bufferDigest,
        bufferDigest,
        HAWK_FLOOR_HASH_BYTES
    );
    HawkSha256Bytes(
        (const UCHAR *)&material,
        sizeof(material),
        request->destinationReferenceHash
    );
    RtlSecureZeroMemory(bufferDigest, sizeof(bufferDigest));
    RtlSecureZeroMemory(&material, sizeof(material));
    return !HawkBytesAllZero(
        request->destinationReferenceHash,
        HAWK_FLOOR_HASH_BYTES
    );
}

static UINT64 HawkFileRequestedRights(
    const PFLT_CALLBACK_DATA data,
    HawkFloorPrimitive primitive
) {
    switch (primitive) {
        case HAWK_FLOOR_FILE_OPEN:
            return HAWK_RIGHT_FILE_OPEN;
        case HAWK_FLOOR_FILE_READ:
            return HAWK_RIGHT_FILE_READ;
        case HAWK_FLOOR_FILE_WRITE:
        case HAWK_FLOOR_FILE_TRUNCATE:
            return HAWK_RIGHT_FILE_WRITE;
        case HAWK_FLOOR_FILE_CREATE:
            return HAWK_RIGHT_FILE_CREATE;
        case HAWK_FLOOR_FILE_DELETE:
            return HAWK_RIGHT_FILE_DELETE;
        case HAWK_FLOOR_FILE_RENAME:
        case HAWK_FLOOR_FILE_MOVE:
            return HAWK_RIGHT_FILE_RENAME;
        case HAWK_FLOOR_FILE_METADATA_CHANGE:
            return HAWK_RIGHT_FILE_METADATA;
        default:
            break;
    }
    if (data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        return ((UINT64)data->Iopb->Parameters.FileSystemControl.Common.FsControlCode << 32) |
            HAWK_RIGHT_FILE_WRITE;
    }
    return 1ULL << (UINT32)primitive;
}

static HawkFloorPrimitive HawkFilePrimitive(PFLT_CALLBACK_DATA data) {
    switch (data->Iopb->MajorFunction) {
        case IRP_MJ_READ: return HAWK_FLOOR_FILE_READ;
        case IRP_MJ_WRITE: return HAWK_FLOOR_FILE_WRITE;
        case IRP_MJ_SET_INFORMATION:
            switch (data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
                case FileDispositionInformation:
                case FileDispositionInformationEx:
                    return HAWK_FLOOR_FILE_DELETE;
                case FileRenameInformation:
                case FileRenameInformationEx:
                case FileShortNameInformation:
                    return HAWK_FLOOR_FILE_RENAME;
                case FileLinkInformation:
                case FileLinkInformationEx:
                    return HAWK_FLOOR_FILE_CREATE;
                case FileEndOfFileInformation:
                case FileAllocationInformation:
                    return HAWK_FLOOR_FILE_TRUNCATE;
                case FileValidDataLengthInformation:
                    return HAWK_FLOOR_FILE_WRITE;
                default:
                    return HAWK_FLOOR_FILE_METADATA_CHANGE;
            }
        case IRP_MJ_SET_EA:
            return HAWK_FLOOR_FILE_METADATA_CHANGE;
        case IRP_MJ_CREATE:
            return HAWK_FLOOR_FILE_OPEN;
        case IRP_MJ_FILE_SYSTEM_CONTROL:
            /* Conservatively authorize all FSCTLs as file mutation. */
            return HAWK_FLOOR_FILE_WRITE;
        case IRP_MJ_DIRECTORY_CONTROL:
        case IRP_MJ_QUERY_INFORMATION:
            return HAWK_FLOOR_FILE_READ;
        case IRP_MJ_SET_SECURITY:
            return HAWK_FLOOR_FILE_WRITE;
        default: return HAWK_FLOOR_UNKNOWN_ENDPOINT_ACTION;
    }
}

static BOOLEAN HawkSetInformationReplacesDestination(
    PFLT_CALLBACK_DATA data,
    BOOLEAN *replacesDestination
) {
    if (data == NULL || replacesDestination == NULL) return FALSE;
    *replacesDestination = FALSE;
    if (data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) return TRUE;

    const FILE_INFORMATION_CLASS informationClass =
        data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (informationClass != FileRenameInformation &&
        informationClass != FileRenameInformationEx &&
        informationClass != FileLinkInformation &&
        informationClass != FileLinkInformationEx) {
        return TRUE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    const ULONG length = data->Iopb->Parameters.SetFileInformation.Length;
    const VOID *buffer = data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    const BOOLEAN extended = informationClass == FileRenameInformationEx ||
        informationClass == FileLinkInformationEx;
    const ULONG required = extended ? sizeof(ULONG) : sizeof(BOOLEAN);
    if (buffer == NULL || length < required || length > 65536U) return FALSE;
    __try {
        if (informationClass == FileRenameInformationEx) {
            *replacesDestination =
                (*(const ULONG *)buffer & FILE_RENAME_REPLACE_IF_EXISTS) != 0;
        } else if (informationClass == FileLinkInformationEx) {
            *replacesDestination =
                (*(const ULONG *)buffer & FILE_LINK_REPLACE_IF_EXISTS) != 0;
        } else {
            *replacesDestination = *(const BOOLEAN *)buffer != FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *replacesDestination = FALSE;
        return FALSE;
    }
    return TRUE;
}

static HawkKernelDecision HawkEvaluateFilePrimitive(
    HawkFloorRequest *request,
    HawkFloorPrimitive primitive,
    const PFLT_CALLBACK_DATA data,
    BOOLEAN permitBindingComplete
) {
    request->primitive = primitive;
    request->requestedRights = HawkFileRequestedRights(data, primitive);
    return HawkEvaluateRequest(request, permitBindingComplete);
}

HawkKernelDecision HawkFloorEvaluateFile(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects) {
    if (!HawkPolicyIsArmed()) return HawkKernelAllow;
    HawkFloorRequest request;
    RtlZeroMemory(&request, sizeof(request));
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    const HawkFloorPrimitive primitive = HawkFilePrimitive(data);
    if (primitive == HAWK_FLOOR_UNKNOWN_ENDPOINT_ACTION) return HawkKernelAllow;
    request.resourceClassification = HAWK_CLASSIFICATION_UNKNOWN;
    request.destinationClassification = HAWK_CLASSIFICATION_UNKNOWN;
    const HANDLE processId = ULongToHandle(FltGetRequestorProcessId(data));
    UCHAR actualBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN governedLineage = FALSE;
    BOOLEAN lineageAuthoritative = FALSE;
    BOOLEAN stableIdentityVerified = FALSE;
    if (!HawkLookupProcessIdentity(
            processId,
            actualBinaryHash,
            request.binaryIdentityHash,
            request.processInstanceHash,
            familyRootInstanceHash,
            &governedLineage,
            &lineageAuthoritative
        ) || !HawkIdentityCoverageReady() ||
        !HawkBindFileIdentity(
            data,
            objects,
            &request,
            &stableIdentityVerified
        ) ||
        !HawkBindSetInformationDestination(data, &request)) {
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    if (HawkLineageRequiresFailClosed(
            request.binaryIdentityHash,
            governedLineage,
            lineageAuthoritative
        )) {
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    RtlCopyMemory(
        request.processIdentityHash,
        actualBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
    RtlSecureZeroMemory(
        familyRootInstanceHash,
        sizeof(familyRootInstanceHash)
    );
    /*
     * File object identity is retained as evidence context only. Exact file
     * permits remain disabled until a post-create/retry design proves the
     * target before user mode can observe the handle and adds object-version
     * binding. Local deterministic policy still authorizes or denies every
     * registered file callback.
     */
    UNREFERENCED_PARAMETER(stableIdentityVerified);
    const BOOLEAN permitBindingComplete = FALSE;
    if (data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        BOOLEAN replacesDestination = FALSE;
        if (!HawkSetInformationReplacesDestination(
                data,
                &replacesDestination
            )) {
            InterlockedIncrement64(&gHawkBlockCount);
            return HawkKernelBlock;
        }
        if (replacesDestination) {
            const HawkKernelDecision replacementDecision =
                HawkEvaluateFilePrimitive(
                    &request,
                    HAWK_FLOOR_FILE_DELETE,
                    data,
                    permitBindingComplete
                );
            if (replacementDecision != HawkKernelAllow) {
                return replacementDecision;
            }
        }
        return HawkEvaluateFilePrimitive(
            &request,
            primitive,
            data,
            permitBindingComplete
        );
    }
    if (data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return HawkEvaluateFilePrimitive(
            &request,
            primitive,
            data,
            permitBindingComplete
        );
    }

    const ULONG packedOptions = data->Iopb->Parameters.Create.Options;
    const ULONG createOptions = packedOptions & 0x00ffffffU;
    const UCHAR disposition = (UCHAR)((packedOptions >> 24) & 0xffU);
    HawkKernelDecision decision;
    const ACCESS_MASK desiredAccess =
        data->Iopb->Parameters.Create.SecurityContext != NULL
        ? data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : 0;
    if ((createOptions & FILE_DELETE_ON_CLOSE) != 0 ||
        (desiredAccess & DELETE) != 0 || disposition == FILE_SUPERSEDE) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_DELETE,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    if (disposition == FILE_SUPERSEDE || disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF || disposition == FILE_OVERWRITE_IF) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_CREATE,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF ||
        (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER)) != 0) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_WRITE,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_TRUNCATE,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    if ((desiredAccess & (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES)) != 0) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_READ,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    if ((desiredAccess & FILE_EXECUTE) != 0) {
        decision = HawkEvaluateFilePrimitive(
            &request,
            HAWK_FLOOR_FILE_EXECUTE,
            data,
            permitBindingComplete
        );
        if (decision != HawkKernelAllow) return decision;
    }
    return HawkEvaluateFilePrimitive(
        &request,
        HAWK_FLOOR_FILE_OPEN,
        data,
        permitBindingComplete
    );
}

typedef enum HawkNetworkBindingStatus {
    HawkNetworkBindingInvalid = 0,
    HawkNetworkBindingBound = 1,
    HawkNetworkBindingUnavailable = 2
} HawkNetworkBindingStatus;

static HawkNetworkBindingStatus HawkBindNetworkDestination(
    const FWPS_INCOMING_VALUES0 *fixedValues,
    HawkFloorRequest *request
) {
    if (fixedValues == NULL || request == NULL) {
        return HawkNetworkBindingInvalid;
    }
    HawkWindowsNetworkDestinationMaterial material;
    UCHAR addressBytes[16];
    UINT16 remotePort = 0;
    UCHAR protocol = 0;
    UCHAR family = 0;
    UINT32 remoteInterfaceIndex = 0;
    SIZE_T addressLength = 0;
    RtlZeroMemory(addressBytes, sizeof(addressBytes));
    if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        const FWP_VALUE0 *protocolValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
        ].value;
        const FWP_VALUE0 *portValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
        ].value;
        const FWP_VALUE0 *addressValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS
        ].value;
        const FWP_VALUE0 *interfaceValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX
        ].value;
        if (protocolValue->type == FWP_EMPTY || portValue->type == FWP_EMPTY ||
            addressValue->type == FWP_EMPTY ||
            interfaceValue->type == FWP_EMPTY) {
            return HawkNetworkBindingUnavailable;
        }
        if (protocolValue->type != FWP_UINT8 ||
            portValue->type != FWP_UINT16 ||
            addressValue->type != FWP_UINT32 ||
            interfaceValue->type != FWP_UINT32) {
            return HawkNetworkBindingInvalid;
        }
        family = 4;
        protocol = protocolValue->uint8;
        remotePort = portValue->uint16;
        const UINT32 address = addressValue->uint32;
        addressBytes[0] = (UCHAR)(address >> 24U);
        addressBytes[1] = (UCHAR)(address >> 16U);
        addressBytes[2] = (UCHAR)(address >> 8U);
        addressBytes[3] = (UCHAR)address;
        remoteInterfaceIndex = interfaceValue->uint32;
        addressLength = 4;
    } else if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        const FWP_VALUE0 *protocolValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL
        ].value;
        const FWP_VALUE0 *portValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT
        ].value;
        const FWP_VALUE0 *addressValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS
        ].value;
        const FWP_VALUE0 *interfaceValue = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX
        ].value;
        if (protocolValue->type == FWP_EMPTY || portValue->type == FWP_EMPTY ||
            addressValue->type == FWP_EMPTY ||
            interfaceValue->type == FWP_EMPTY) {
            return HawkNetworkBindingUnavailable;
        }
        if (protocolValue->type != FWP_UINT8 ||
            portValue->type != FWP_UINT16 ||
            addressValue->type != FWP_BYTE_ARRAY16_TYPE ||
            interfaceValue->type != FWP_UINT32) {
            return HawkNetworkBindingInvalid;
        }
        family = 6;
        protocol = protocolValue->uint8;
        remotePort = portValue->uint16;
        const FWP_BYTE_ARRAY16 *address = addressValue->byteArray16;
        if (address == NULL) return HawkNetworkBindingInvalid;
        RtlCopyMemory(addressBytes, address->byteArray16, 16);
        remoteInterfaceIndex = interfaceValue->uint32;
        addressLength = 16;
    } else {
        return HawkNetworkBindingInvalid;
    }
    if (!HawkWindowsBuildNetworkDestinationMaterial(
            family,
            protocol,
            remotePort,
            remoteInterfaceIndex,
            addressBytes,
            addressLength,
            &material,
            &request->requestedRights
        )) {
        RtlSecureZeroMemory(addressBytes, sizeof(addressBytes));
        return HawkNetworkBindingInvalid;
    }
    HawkSha256Bytes(
        (const UCHAR *)&material,
        sizeof(material),
        request->destinationReferenceHash
    );
    RtlSecureZeroMemory(addressBytes, sizeof(addressBytes));
    RtlSecureZeroMemory(&material, sizeof(material));
    return request->requestedRights != 0 && !HawkBytesAllZero(
            request->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        ) ? HawkNetworkBindingBound : HawkNetworkBindingInvalid;
}

static BOOLEAN HawkNetworkPriorAuthorizationCurrent(
    const HawkNetworkAuthorizationState *authorization,
    const HawkPolicyAllocation *policy,
    UINT64 evaluationArmEpoch
) {
    return authorization != NULL && policy != NULL &&
        HawkIdentityCoverageReady() &&
        authorization->version == HAWK_NETWORK_AUTHORIZATION_STATE_VERSION &&
        authorization->reserved == 0 &&
        authorization->policyGeneration == policy->generation &&
        authorization->policySequence == policy->policySequence &&
        authorization->armSessionEpoch == evaluationArmEpoch &&
        policy->snapshot.expiresAtMonotonicNs > HawkMonotonicNanoseconds() &&
        authorization->requestedRights != 0 &&
        !HawkBytesAllZero(
            authorization->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        !HawkBytesAllZero(
            authorization->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        );
}

static BOOLEAN HawkPolicyChangeReauthorization(
    const FWPS_INCOMING_VALUES0 *fixedValues
) {
    if (fixedValues == NULL) return FALSE;
    const FWP_VALUE0 *reason = NULL;
    if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        reason = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON
        ].value;
    } else if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        reason = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_REAUTHORIZE_REASON
        ].value;
    }
    return reason != NULL && reason->type == FWP_UINT32 &&
        reason->uint32 == FWP_CONDITION_REAUTHORIZE_REASON_POLICY_CHANGE;
}

HawkKernelDecision HawkFloorEvaluateNetwork(
    const FWPS_INCOMING_VALUES0 *fixedValues,
    const FWPS_INCOMING_METADATA_VALUES0 *metadataValues,
    const HawkNetworkAuthorizationState *priorAuthorization,
    HawkNetworkAuthorizationState *authorization
) {
    if (authorization == NULL) return HawkKernelBlock;
    RtlZeroMemory(authorization, sizeof(*authorization));
    UINT64 evaluationArmEpoch = 0;
    if (!HawkCaptureArmSessionEpoch(&evaluationArmEpoch)) {
        return HawkKernelAllow;
    }

    HawkFloorRequest request;
    RtlZeroMemory(&request, sizeof(request));
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HAWK_FLOOR_NETWORK_CONNECT;
    request.resourceClassification = HAWK_CLASSIFICATION_UNKNOWN;
    request.destinationClassification = HAWK_CLASSIFICATION_UNKNOWN;
    UCHAR actualBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    RtlZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
    RtlZeroMemory(familyRootInstanceHash, sizeof(familyRootInstanceHash));
    BOOLEAN governedLineage = FALSE;
    BOOLEAN lineageAuthoritative = FALSE;

    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    if (policy == NULL) {
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }

    /*
     * A WFP flow context is bound by the filtering engine to the exact ALE
     * flow. Reauthorization can omit process or destination fields, so first
     * validate the stored authority against the live Hawk policy and arm
     * session. When Windows supplies fresh fields, they must still match.
     * Missing destination material is reusable only for a pure WFP policy
     * change; interface/profile changes fail closed because the v3 binding
     * includes the interface index.
     */
    if (HawkNetworkPriorAuthorizationCurrent(
            priorAuthorization,
            policy,
            evaluationArmEpoch
        )) {
        if (metadataValues != NULL && FWPS_IS_METADATA_FIELD_PRESENT(
                metadataValues,
                FWPS_METADATA_FIELD_PROCESS_ID
            )) {
            if (!HawkLookupProcessIdentity(
                    (HANDLE)(ULONG_PTR)metadataValues->processId,
                    actualBinaryHash,
                    request.binaryIdentityHash,
                    request.processInstanceHash,
                    familyRootInstanceHash,
                    &governedLineage,
                    &lineageAuthoritative
                ) || !HawkIdentityCoverageReady() ||
                !lineageAuthoritative ||
                !HawkBinaryGoverned(
                    &policy->snapshot,
                    HAWK_FLOOR_NETWORK_CONNECT,
                    request.binaryIdentityHash
                ) || !HawkBytesEqual(
                    priorAuthorization->processInstanceHash,
                    request.processInstanceHash,
                    HAWK_FLOOR_HASH_BYTES
                )) {
                HawkReleasePolicy(policy);
                RtlSecureZeroMemory(
                    actualBinaryHash,
                    sizeof(actualBinaryHash)
                );
                RtlSecureZeroMemory(
                    familyRootInstanceHash,
                    sizeof(familyRootInstanceHash)
                );
                InterlockedIncrement64(&gHawkBlockCount);
                return HawkKernelBlock;
            }
        }

        const HawkNetworkBindingStatus bindingStatus =
            HawkBindNetworkDestination(fixedValues, &request);
        if (bindingStatus == HawkNetworkBindingInvalid ||
            (bindingStatus == HawkNetworkBindingUnavailable &&
                !HawkPolicyChangeReauthorization(fixedValues)) ||
            (bindingStatus == HawkNetworkBindingBound &&
                (priorAuthorization->requestedRights !=
                    request.requestedRights || !HawkBytesEqual(
                        priorAuthorization->destinationReferenceHash,
                        request.destinationReferenceHash,
                        HAWK_FLOOR_HASH_BYTES
                    )))) {
            HawkReleasePolicy(policy);
            RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
            RtlSecureZeroMemory(
                familyRootInstanceHash,
                sizeof(familyRootInstanceHash)
            );
            InterlockedIncrement64(&gHawkBlockCount);
            return HawkKernelBlock;
        }

        /*
         * Linearize the allow against disarm/rearm. A transition that wins
         * this race invalidates the old authority rather than letting it be
         * stamped with the new arm-session epoch.
         */
        if (!HawkArmSessionCurrent(evaluationArmEpoch)) {
            HawkReleasePolicy(policy);
            RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
            RtlSecureZeroMemory(
                familyRootInstanceHash,
                sizeof(familyRootInstanceHash)
            );
            InterlockedIncrement64(&gHawkBlockCount);
            return HawkKernelBlock;
        }
        RtlCopyMemory(
            authorization,
            priorAuthorization,
            sizeof(*authorization)
        );
        HawkReleasePolicy(policy);
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkAllowCount);
        return HawkKernelAllow;
    }

    if (metadataValues == NULL ||
        !FWPS_IS_METADATA_FIELD_PRESENT(
            metadataValues,
            FWPS_METADATA_FIELD_PROCESS_ID
        ) || !HawkLookupProcessIdentity(
            (HANDLE)(ULONG_PTR)metadataValues->processId,
            actualBinaryHash,
            request.binaryIdentityHash,
            request.processInstanceHash,
            familyRootInstanceHash,
            &governedLineage,
            &lineageAuthoritative
        ) || !HawkIdentityCoverageReady()) {
        HawkReleasePolicy(policy);
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    if (HawkLineageRequiresFailClosed(
            request.binaryIdentityHash,
            governedLineage,
            lineageAuthoritative
        )) {
        HawkReleasePolicy(policy);
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    if (!HawkBinaryGoverned(
            &policy->snapshot,
            HAWK_FLOOR_NETWORK_CONNECT,
            request.binaryIdentityHash
        )) {
        HawkReleasePolicy(policy);
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkAllowCount);
        return HawkKernelAllow;
    }
    if (HawkBindNetworkDestination(fixedValues, &request) !=
            HawkNetworkBindingBound) {
        HawkReleasePolicy(policy);
        RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
        RtlSecureZeroMemory(
            familyRootInstanceHash,
            sizeof(familyRootInstanceHash)
        );
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    RtlCopyMemory(
        request.processIdentityHash,
        actualBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlSecureZeroMemory(actualBinaryHash, sizeof(actualBinaryHash));
    RtlSecureZeroMemory(
        familyRootInstanceHash,
        sizeof(familyRootInstanceHash)
    );
    const HawkKernelDecision decision = HawkEvaluateRequestWithPolicy(
        &request,
        TRUE,
        policy
    );
    if (decision == HawkKernelAllow) {
        if (!HawkArmSessionCurrent(evaluationArmEpoch)) {
            /* HawkEvaluateRequestWithPolicy already counted this as allow. */
            InterlockedDecrement64(&gHawkAllowCount);
            InterlockedIncrement64(&gHawkBlockCount);
            RtlZeroMemory(authorization, sizeof(*authorization));
            HawkReleasePolicy(policy);
            return HawkKernelBlock;
        }
        authorization->version = HAWK_NETWORK_AUTHORIZATION_STATE_VERSION;
        authorization->policyGeneration = policy->generation;
        authorization->policySequence = policy->policySequence;
        authorization->armSessionEpoch = evaluationArmEpoch;
        authorization->requestedRights = request.requestedRights;
        RtlCopyMemory(
            authorization->processInstanceHash,
            request.processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            authorization->destinationReferenceHash,
            request.destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        );
    }
    HawkReleasePolicy(policy);
    return decision;
}

static BOOLEAN HawkBuildProcessLaunchIdentity(
    PCUNICODE_STRING targetImageFileName,
    PCUNICODE_STRING commandLine,
    UCHAR launchIdentityHash[HAWK_FLOOR_HASH_BYTES]
) {
    if (targetImageFileName == NULL || targetImageFileName->Buffer == NULL ||
        targetImageFileName->Length == 0 || launchIdentityHash == NULL) {
        return FALSE;
    }
    struct {
        UCHAR domain[40];
        UCHAR targetBinaryHash[HAWK_FLOOR_HASH_BYTES];
        UINT32 commandLineLength;
        UINT32 reserved;
        UCHAR commandLineHash[HAWK_FLOOR_HASH_BYTES];
    } material;
    C_ASSERT(sizeof("hawk.windows.process-launch.v1") <=
        sizeof(material.domain));
    RtlZeroMemory(&material, sizeof(material));
    RtlCopyMemory(
        material.domain,
        "hawk.windows.process-launch.v1",
        sizeof("hawk.windows.process-launch.v1")
    );
    HawkSha256UnicodeInsensitive(
        targetImageFileName,
        material.targetBinaryHash
    );
    BOOLEAN commandObserved = FALSE;
    if (commandLine != NULL && commandLine->Buffer != NULL &&
        commandLine->Length > 0 &&
        (commandLine->Length % sizeof(WCHAR)) == 0) {
        __try {
            material.commandLineLength = commandLine->Length;
            HawkSha256Bytes(
                (const UCHAR *)commandLine->Buffer,
                commandLine->Length,
                material.commandLineHash
            );
            commandObserved = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            material.commandLineLength = 0;
            RtlZeroMemory(
                material.commandLineHash,
                sizeof(material.commandLineHash)
            );
        }
    }
    HawkSha256Bytes(
        (const UCHAR *)&material,
        sizeof(material),
        launchIdentityHash
    );
    RtlSecureZeroMemory(&material, sizeof(material));
    /*
     * Raw command material is useful evidence, but it is not sufficient for
     * a process permit: an interpreter script/module, environment expansion,
     * or same-path executable replacement can change the actual code while
     * preserving this string. Keep process permit matching disabled until the
     * opened executable object and resolved script/module authority are bound.
     */
    UNREFERENCED_PARAMETER(commandObserved);
    return FALSE;
}

static BOOLEAN HawkCrossGovernedFamilyConflict(
    BOOLEAN actorGovernedLineage,
    const UCHAR actorPolicyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    BOOLEAN targetDirectlyGoverned,
    const UCHAR targetActualBinaryHash[HAWK_FLOOR_HASH_BYTES]
) {
    return actorGovernedLineage && targetDirectlyGoverned &&
        !HawkBytesEqual(
            actorPolicyBinaryHash,
            targetActualBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
}

static HawkKernelDecision HawkEvaluateProcessWithPolicy(
    PEPROCESS targetProcess,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo,
    PCUNICODE_STRING targetImageFileName,
    HawkProcessLineageSeed *targetIdentity,
    HawkPolicyAllocation *policy
) {
    RtlZeroMemory(targetIdentity, sizeof(*targetIdentity));
    if (!HawkBuildProcessIdentity(
            processId,
            targetProcess,
            targetImageFileName,
            targetIdentity->actualBinaryHash,
            targetIdentity->processInstanceHash
        )) {
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    UCHAR launchIdentityHash[HAWK_FLOOR_HASH_BYTES];
    targetIdentity->launchMaterialComplete = HawkBuildProcessLaunchIdentity(
        targetImageFileName,
        createInfo->CommandLine,
        launchIdentityHash
    );
    if (HawkBytesAllZero(launchIdentityHash, sizeof(launchIdentityHash))) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }

    const HANDLE actorId = createInfo->CreatingThreadId.UniqueProcess != NULL
        ? createInfo->CreatingThreadId.UniqueProcess : createInfo->ParentProcessId;
    UCHAR actorActualBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR actorPolicyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR actorProcessInstanceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR actorFamilyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN actorGovernedLineage = FALSE;
    BOOLEAN actorLineageAuthoritative = FALSE;
    if (!HawkLookupProcessIdentity(
            actorId,
            actorActualBinaryHash,
            actorPolicyBinaryHash,
            actorProcessInstanceHash,
            actorFamilyRootInstanceHash,
            &actorGovernedLineage,
            &actorLineageAuthoritative
        )) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        RtlSecureZeroMemory(launchIdentityHash, sizeof(launchIdentityHash));
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    if (!HawkIdentityCoverageReady() || HawkLineageRequiresFailClosed(
            actorPolicyBinaryHash,
            actorGovernedLineage,
            actorLineageAuthoritative
        )) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        RtlSecureZeroMemory(launchIdentityHash, sizeof(launchIdentityHash));
        RtlSecureZeroMemory(actorActualBinaryHash, sizeof(actorActualBinaryHash));
        RtlSecureZeroMemory(actorPolicyBinaryHash, sizeof(actorPolicyBinaryHash));
        RtlSecureZeroMemory(actorProcessInstanceHash, sizeof(actorProcessInstanceHash));
        RtlSecureZeroMemory(actorFamilyRootInstanceHash, sizeof(actorFamilyRootInstanceHash));
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    const BOOLEAN targetDirectlyGoverned =
        HawkImageIsGoverned(targetImageFileName);
    if (HawkCrossGovernedFamilyConflict(
            actorGovernedLineage,
            actorPolicyBinaryHash,
            targetDirectlyGoverned,
            targetIdentity->actualBinaryHash
        )) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        RtlSecureZeroMemory(launchIdentityHash, sizeof(launchIdentityHash));
        RtlSecureZeroMemory(actorActualBinaryHash, sizeof(actorActualBinaryHash));
        RtlSecureZeroMemory(actorPolicyBinaryHash, sizeof(actorPolicyBinaryHash));
        RtlSecureZeroMemory(actorProcessInstanceHash, sizeof(actorProcessInstanceHash));
        RtlSecureZeroMemory(actorFamilyRootInstanceHash, sizeof(actorFamilyRootInstanceHash));
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    targetIdentity->governedLineage =
        actorGovernedLineage || targetDirectlyGoverned;
    targetIdentity->lineageAuthoritative =
        actorLineageAuthoritative || targetDirectlyGoverned;
    if (actorGovernedLineage) {
        RtlCopyMemory(
            targetIdentity->policyBinaryHash,
            actorPolicyBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            targetIdentity->familyRootInstanceHash,
            actorFamilyRootInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
    } else {
        RtlCopyMemory(
            targetIdentity->policyBinaryHash,
            targetIdentity->actualBinaryHash,
            HAWK_FLOOR_HASH_BYTES
        );
        RtlCopyMemory(
            targetIdentity->familyRootInstanceHash,
            targetIdentity->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        );
    }

    HawkFloorRequest request;
    RtlZeroMemory(&request, sizeof(request));
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HAWK_FLOOR_PROCESS_CHILD_CREATE;
    request.requestedRights = HAWK_RIGHT_PROCESS_CHILD_CREATE;
    request.resourceClassification = HAWK_CLASSIFICATION_UNKNOWN;
    request.destinationClassification = HAWK_CLASSIFICATION_UNKNOWN;
    RtlCopyMemory(
        request.binaryIdentityHash,
        actorPolicyBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.processIdentityHash,
        actorActualBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.processInstanceHash,
        actorProcessInstanceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.stableResourceIdentityHash,
        launchIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.resourceReferenceHash,
        launchIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    const HawkKernelDecision childDecision = HawkEvaluateRequestWithPolicy(
        &request,
        targetIdentity->launchMaterialComplete,
        policy
    );
    if (childDecision != HawkKernelAllow) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        RtlSecureZeroMemory(launchIdentityHash, sizeof(launchIdentityHash));
        RtlSecureZeroMemory(actorActualBinaryHash, sizeof(actorActualBinaryHash));
        RtlSecureZeroMemory(actorPolicyBinaryHash, sizeof(actorPolicyBinaryHash));
        RtlSecureZeroMemory(actorProcessInstanceHash, sizeof(actorProcessInstanceHash));
        RtlSecureZeroMemory(actorFamilyRootInstanceHash, sizeof(actorFamilyRootInstanceHash));
        return childDecision;
    }

    RtlZeroMemory(&request, sizeof(request));
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HAWK_FLOOR_PROCESS_EXECUTE;
    request.requestedRights = HAWK_RIGHT_PROCESS_EXECUTE;
    request.resourceClassification = HAWK_CLASSIFICATION_UNKNOWN;
    request.destinationClassification = HAWK_CLASSIFICATION_UNKNOWN;
    RtlCopyMemory(
        request.binaryIdentityHash,
        targetIdentity->policyBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.processIdentityHash,
        targetIdentity->actualBinaryHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.processInstanceHash,
        targetIdentity->processInstanceHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.stableResourceIdentityHash,
        launchIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    RtlCopyMemory(
        request.resourceReferenceHash,
        launchIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    const HawkKernelDecision targetDecision = HawkEvaluateRequestWithPolicy(
        &request,
        targetIdentity->launchMaterialComplete,
        policy
    );
    RtlSecureZeroMemory(launchIdentityHash, sizeof(launchIdentityHash));
    RtlSecureZeroMemory(actorActualBinaryHash, sizeof(actorActualBinaryHash));
    RtlSecureZeroMemory(actorPolicyBinaryHash, sizeof(actorPolicyBinaryHash));
    RtlSecureZeroMemory(actorProcessInstanceHash, sizeof(actorProcessInstanceHash));
    RtlSecureZeroMemory(actorFamilyRootInstanceHash, sizeof(actorFamilyRootInstanceHash));
    if (targetDecision != HawkKernelAllow) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
    }
    return targetDecision;
}

HawkKernelDecision HawkFloorEvaluateProcess(
    PEPROCESS targetProcess,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo,
    PCUNICODE_STRING targetImageFileName,
    HawkProcessLineageSeed *targetIdentity
) {
    HawkAcquireControlTransitionLock();
    if (targetProcess == NULL || processId == NULL || createInfo == NULL ||
        targetImageFileName == NULL || targetImageFileName->Buffer == NULL ||
        targetImageFileName->Length == 0 || targetIdentity == NULL) {
        if (HawkPolicyIsArmed()) {
            InterlockedIncrement64(&gHawkBlockCount);
            HawkReleaseControlTransitionLock();
            return HawkKernelBlock;
        }
        HawkReleaseControlTransitionLock();
        return HawkKernelAllow;
    }

    if (!HawkPolicyIsArmed()) {
        const BOOLEAN directlyGoverned =
            HawkImageIsGoverned(targetImageFileName);
        const HANDLE actorId =
            createInfo->CreatingThreadId.UniqueProcess != NULL
                ? createInfo->CreatingThreadId.UniqueProcess
                : createInfo->ParentProcessId;
        const BOOLEAN remembered = HawkRestoreSeededProcessLineage(
            processId,
            actorId,
            targetProcess,
            targetImageFileName,
            TRUE
        );
        const BOOLEAN denyForIdentityFailure = !remembered &&
            directlyGoverned;
        HawkReleaseControlTransitionLock();
        if (denyForIdentityFailure) {
            InterlockedIncrement64(&gHawkBlockCount);
            return HawkKernelBlock;
        }
        return HawkKernelAllow;
    }

    HawkPolicyAllocation *policy = HawkAcquirePolicy();
    if (policy == NULL) {
        HawkReleaseControlTransitionLock();
        InterlockedIncrement64(&gHawkPolicyRejectCount);
        InterlockedIncrement64(&gHawkBlockCount);
        return HawkKernelBlock;
    }
    HawkKernelDecision decision = HawkEvaluateProcessWithPolicy(
        targetProcess,
        processId,
        createInfo,
        targetImageFileName,
        targetIdentity,
        policy
    );
    if (decision == HawkKernelAllow && !HawkRememberProcessIdentity(
            processId,
            targetProcess,
            targetImageFileName,
            targetIdentity
        )) {
        RtlSecureZeroMemory(targetIdentity, sizeof(*targetIdentity));
        InterlockedIncrement64(&gHawkBlockCount);
        decision = HawkKernelBlock;
    }
    HawkReleasePolicy(policy);
    HawkReleaseControlTransitionLock();
    return decision;
}
