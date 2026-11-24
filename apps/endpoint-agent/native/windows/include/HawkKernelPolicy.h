#ifndef HAWK_KERNEL_POLICY_H
#define HAWK_KERNEL_POLICY_H

#include <fltKernel.h>
#include <fwpsk.h>
#include "HawkKernelPolicyIoctl.h"

typedef enum HawkKernelDecision {
    HawkKernelAllow = 0,
    HawkKernelBlock = 1,
    HawkKernelLocalEscalationRequired = 2
} HawkKernelDecision;

typedef struct HawkProcessLineageSeed {
    UCHAR actualBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR policyBinaryHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    BOOLEAN governedLineage;
    BOOLEAN launchMaterialComplete;
    BOOLEAN lineageAuthoritative;
    /*
     * Internal-only recovery contract. This may be set only when a complete
     * process snapshot proves the process is still live but its parent has
     * already disappeared. It deliberately converts any stale authoritative
     * lineage for the same process instance into governed/non-authoritative
     * identity so consequences fail closed until a protected create callback
     * supplies exact lineage again.
     */
    BOOLEAN allowConservativeAuthorityDowngrade;
    UCHAR reserved[4];
} HawkProcessLineageSeed;

#define HAWK_NETWORK_AUTHORIZATION_STATE_VERSION 2U

typedef struct HawkNetworkAuthorizationState {
    UINT32 version;
    UINT32 reserved;
    UINT64 policyGeneration;
    UINT64 policySequence;
    UINT64 armSessionEpoch;
    UINT64 requestedRights;
    UCHAR processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    UCHAR destinationReferenceHash[HAWK_FLOOR_HASH_BYTES];
} HawkNetworkAuthorizationState;

NTSTATUS HawkInitializeKernelPolicy(VOID);
VOID HawkShutdownKernelPolicy(VOID);
NTSTATUS HawkFloorPublishSnapshot(
    _In_reads_bytes_(InputBytes) const VOID *Input,
    _In_ ULONG InputBytes
);
NTSTATUS HawkSetPolicyArmed(
    _In_ BOOLEAN Armed,
    _In_ UINT64 ExpectedGeneration
);
VOID HawkGetPolicyStatus(_Out_ HawkWindowsPolicyStatus *Status);
NTSTATUS HawkSeedProcessIdentities(
    _In_reads_(ProcessCount) const HawkWindowsProcessSeedEntry *Processes,
    _In_ ULONG ProcessCount
);
NTSTATUS HawkFloorPublishPermits(
    _In_reads_bytes_(InputBytes) const VOID *Input,
    _In_ ULONG InputBytes
);
BOOLEAN HawkIdentityCoverageReady(VOID);
BOOLEAN HawkWfpReady(VOID);
NTSTATUS HawkWfpReauthorizeFlows(VOID);
BOOLEAN HawkEnforcementArmed(VOID);

BOOLEAN HawkRememberProcessIdentity(
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS Process,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_opt_ const HawkProcessLineageSeed *LineageSeed
);
BOOLEAN HawkImageIsGoverned(
    _In_ PCUNICODE_STRING ImageFileName
);
VOID HawkForgetProcessIdentity(_In_ HANDLE ProcessId);
BOOLEAN HawkLookupProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_writes_(HAWK_FLOOR_HASH_BYTES) UCHAR ActualBinaryHash[HAWK_FLOOR_HASH_BYTES],
    _Out_writes_(HAWK_FLOOR_HASH_BYTES) UCHAR PolicyBinaryHash[HAWK_FLOOR_HASH_BYTES],
    _Out_writes_(HAWK_FLOOR_HASH_BYTES) UCHAR ProcessInstanceHash[HAWK_FLOOR_HASH_BYTES],
    _Out_writes_(HAWK_FLOOR_HASH_BYTES) UCHAR FamilyRootInstanceHash[HAWK_FLOOR_HASH_BYTES],
    _Out_ BOOLEAN *GovernedLineage,
    _Out_ BOOLEAN *LineageAuthoritative
);
NTSTATUS HawkQueryProcessIdentity(
    _In_ UINT64 ProcessId,
    _Out_ HawkWindowsProcessIdentityResponse *Response
);

// All three functions read only the bounded, signature-verified local snapshot
// installed by the Hawk Windows service. They never perform user-mode or cloud
// calls from an OS-critical callback.
HawkKernelDecision HawkFloorEvaluateFile(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
);

HawkKernelDecision HawkFloorEvaluateNetwork(
    _In_ const FWPS_INCOMING_VALUES0 *FixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *MetadataValues,
    _In_opt_ const HawkNetworkAuthorizationState *PriorAuthorization,
    _Out_ HawkNetworkAuthorizationState *Authorization
);

HawkKernelDecision HawkFloorEvaluateProcess(
    _In_ PEPROCESS TargetProcess,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _In_ PCUNICODE_STRING TargetImageFileName,
    _Out_ HawkProcessLineageSeed *TargetIdentity
);

#endif
