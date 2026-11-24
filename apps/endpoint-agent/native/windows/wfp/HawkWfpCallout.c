#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../include/HawkKernelPolicy.h"

#define HAWK_WFP_POOL_TAG 'FwkH'

typedef struct HawkWfpFlowContext {
    KSPIN_LOCK lock;
    HawkNetworkAuthorizationState authorization;
} HawkWfpFlowContext;

static UINT32 gHawkConnectV4CalloutId = 0;
static UINT32 gHawkConnectV6CalloutId = 0;
static HANDLE gHawkWfpEngine = NULL;
static HANDLE gHawkBfeChangeHandle = NULL;
static FAST_MUTEX gHawkWfpMutex;
static volatile LONG gHawkWfpReady = 0;
static volatile LONG gHawkActiveFilterBank = -1;

static BOOLEAN HawkWfpIsReauthorization(
    _In_ const FWPS_INCOMING_VALUES0 *fixedValues
) {
    if (fixedValues == NULL) return FALSE;
    const FWP_VALUE0 *flags = NULL;
    if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        flags = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS
        ].value;
    } else if (fixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        flags = &fixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS
        ].value;
    }
    return flags != NULL && flags->type == FWP_UINT32 &&
        (flags->uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0;
}

static VOID NTAPI HawkFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    HawkWfpFlowContext *context = (HawkWfpFlowContext *)(ULONG_PTR)flowContext;
    if (context != NULL) {
        RtlSecureZeroMemory(context, sizeof(*context));
        ExFreePoolWithTag(context, HAWK_WFP_POOL_TAG);
    }
}

static VOID NTAPI HawkClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ VOID *layerData,
    _In_ const FWPS_FILTER0 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut
) {
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }
    HawkNetworkAuthorizationState priorAuthorization;
    HawkNetworkAuthorizationState authorization;
    RtlZeroMemory(&priorAuthorization, sizeof(priorAuthorization));
    RtlZeroMemory(&authorization, sizeof(authorization));
    HawkWfpFlowContext *context =
        (HawkWfpFlowContext *)(ULONG_PTR)flowContext;
    const BOOLEAN reauthorization = HawkWfpIsReauthorization(inFixedValues);
    const HawkNetworkAuthorizationState *prior = NULL;
    if (reauthorization && context != NULL) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&context->lock, &oldIrql);
        RtlCopyMemory(
            &priorAuthorization,
            &context->authorization,
            sizeof(priorAuthorization)
        );
        KeReleaseSpinLock(&context->lock, oldIrql);
        prior = &priorAuthorization;
    }
    const HawkKernelDecision decision = HawkFloorEvaluateNetwork(
        inFixedValues,
        inMetaValues,
        prior,
        &authorization
    );
    if (decision == HawkKernelAllow) {
        if (authorization.version ==
            HAWK_NETWORK_AUTHORIZATION_STATE_VERSION) {
            if (context != NULL) {
                KIRQL oldIrql;
                KeAcquireSpinLock(&context->lock, &oldIrql);
                RtlCopyMemory(
                    &context->authorization,
                    &authorization,
                    sizeof(authorization)
                );
                KeReleaseSpinLock(&context->lock, oldIrql);
            } else if (FWPS_IS_METADATA_FIELD_PRESENT(
                    inMetaValues,
                    FWPS_METADATA_FIELD_FLOW_HANDLE
                )) {
                HawkWfpFlowContext *newContext = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(*newContext),
                    HAWK_WFP_POOL_TAG
                );
                if (newContext != NULL) {
                    RtlZeroMemory(newContext, sizeof(*newContext));
                    KeInitializeSpinLock(&newContext->lock);
                    RtlCopyMemory(
                        &newContext->authorization,
                        &authorization,
                        sizeof(authorization)
                    );
                    const UINT32 calloutId = inFixedValues->layerId ==
                        FWPS_LAYER_ALE_AUTH_CONNECT_V4
                            ? gHawkConnectV4CalloutId
                            : gHawkConnectV6CalloutId;
                    const NTSTATUS associationStatus =
                        FwpsFlowAssociateContext0(
                            inMetaValues->flowHandle,
                            inFixedValues->layerId,
                            calloutId,
                            (UINT64)(ULONG_PTR)newContext
                        );
                    if (!NT_SUCCESS(associationStatus)) {
                        RtlSecureZeroMemory(newContext, sizeof(*newContext));
                        ExFreePoolWithTag(newContext, HAWK_WFP_POOL_TAG);
                    }
                }
            }
        }
        RtlSecureZeroMemory(&priorAuthorization, sizeof(priorAuthorization));
        RtlSecureZeroMemory(&authorization, sizeof(authorization));
        /* Preserve Windows Firewall, IPsec, EDR, and other WFP arbitration. */
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    RtlSecureZeroMemory(&priorAuthorization, sizeof(priorAuthorization));
    RtlSecureZeroMemory(&authorization, sizeof(authorization));
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static NTSTATUS NTAPI HawkNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER0 *filter
) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static const GUID HAWK_CONNECT_V4_CALLOUT =
    {0xa9a84dad, 0x117c, 0x45f7, {0xa0, 0x2c, 0x44, 0xa1, 0x62, 0x1e, 0x98, 0x10}};
static const GUID HAWK_CONNECT_V6_CALLOUT =
    {0x4b8dd1ba, 0x14df, 0x47ae, {0xa9, 0x21, 0x7e, 0x4d, 0x2f, 0x49, 0x81, 0x77}};
static const GUID HAWK_WFP_SUBLAYER =
    {0x0f8d8c44, 0x2f6d, 0x4b5d, {0x91, 0xa0, 0x65, 0x22, 0x2d, 0x66, 0x45, 0xb4}};

/*
 * Alternating deterministic filter keys turn a material Hawk policy change
 * into a real WFP ALE policy change. Microsoft documents that adding or
 * removing a filter at an ALE layer causes existing flows at that layer to be
 * reauthorized on their next packet. The swap is committed in one BFE
 * transaction, so there is no direct-route gap between banks.
 */
static const GUID HAWK_CONNECT_FILTER_KEYS[2][2][2] = {
    {
        {
            {0x0afc3a11, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x01}},
            {0x0afc3a12, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x02}}
        },
        {
            {0x0afc3a13, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x03}},
            {0x0afc3a14, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x04}}
        }
    },
    {
        {
            {0x0afc3a21, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x11}},
            {0x0afc3a22, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x12}}
        },
        {
            {0x0afc3a23, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x13}},
            {0x0afc3a24, 0x7c5d, 0x477a, {0x91, 0xd1, 0x2c, 0xbc, 0x6f, 0xa7, 0x18, 0x14}}
        }
    }
};

static NTSTATUS HawkInstallFilterBank(ULONG bank) {
    if (gHawkWfpEngine == NULL || bank > 1U) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    const GUID *calloutKeys[2] = {
        &HAWK_CONNECT_V4_CALLOUT,
        &HAWK_CONNECT_V6_CALLOUT
    };
    const GUID *layers[2] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6
    };
    const UCHAR protocols[2] = {6U, 17U};
    for (ULONG layerIndex = 0; layerIndex < 2U; ++layerIndex) {
        for (ULONG protocolIndex = 0; protocolIndex < 2U; ++protocolIndex) {
            FWPM_FILTER_CONDITION0 condition = {0};
            condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.type = FWP_UINT8;
            condition.conditionValue.uint8 = protocols[protocolIndex];

            FWPM_FILTER0 filter = {0};
            filter.filterKey =
                HAWK_CONNECT_FILTER_KEYS[bank][layerIndex][protocolIndex];
            filter.displayData.name =
                L"Hawk governed TCP/UDP application authorization";
            filter.layerKey = *layers[layerIndex];
            filter.subLayerKey = HAWK_WFP_SUBLAYER;
            filter.numFilterConditions = 1;
            filter.filterCondition = &condition;
            /* Continue when Hawk permits; veto only a proven governed block. */
            filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
            filter.action.calloutKey = *calloutKeys[layerIndex];
            filter.weight.type = FWP_EMPTY;
            const NTSTATUS status = FwpmFilterAdd0(
                gHawkWfpEngine,
                &filter,
                NULL,
                NULL
            );
            if (!NT_SUCCESS(status)) return status;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HawkDeleteFilterBank(LONG bank) {
    if (gHawkWfpEngine == NULL || bank < 0 || bank > 1) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    for (ULONG layerIndex = 0; layerIndex < 2U; ++layerIndex) {
        for (ULONG protocolIndex = 0; protocolIndex < 2U; ++protocolIndex) {
            const NTSTATUS status = FwpmFilterDeleteByKey0(
                gHawkWfpEngine,
                &HAWK_CONNECT_FILTER_KEYS[bank][layerIndex][protocolIndex]
            );
            if (!NT_SUCCESS(status) && status != FWP_E_FILTER_NOT_FOUND) {
                return status;
            }
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HawkAddWfpPolicyObjects(VOID) {
    if (gHawkWfpEngine != NULL) {
        FwpmEngineClose0(gHawkWfpEngine);
        gHawkWfpEngine = NULL;
    }
    InterlockedExchange(&gHawkWfpReady, 0);
    InterlockedExchange(&gHawkActiveFilterBank, -1);
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"Hawk Endpoint Floor Session";
    NTSTATUS status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &gHawkWfpEngine
    );
    if (!NT_SUCCESS(status)) return status;
    status = FwpmTransactionBegin0(gHawkWfpEngine, 0);
    if (!NT_SUCCESS(status)) goto Failure;

    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = HAWK_WFP_SUBLAYER;
    sublayer.displayData.name = L"Hawk Endpoint Floor";
    sublayer.displayData.description = L"Signed local AI endpoint policy";
    sublayer.weight = 0x7000;
    status = FwpmSubLayerAdd0(gHawkWfpEngine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) goto Abort;

    const GUID *keys[2] = {&HAWK_CONNECT_V4_CALLOUT, &HAWK_CONNECT_V6_CALLOUT};
    const GUID *layers[2] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6};
    for (ULONG index = 0; index < 2; ++index) {
        FWPM_CALLOUT0 managementCallout = {0};
        managementCallout.calloutKey = *keys[index];
        managementCallout.displayData.name = L"Hawk governed application connect";
        managementCallout.applicableLayer = *layers[index];
        status = FwpmCalloutAdd0(gHawkWfpEngine, &managementCallout, NULL, NULL);
        if (!NT_SUCCESS(status)) goto Abort;

    }
    /*
     * Only TCP and UDP reach this Phase-3 path. ALE port fields alias ICMP
     * type/code, so every other protocol stays explicitly unavailable.
     */
    status = HawkInstallFilterBank(0U);
    if (!NT_SUCCESS(status)) goto Abort;
    status = FwpmTransactionCommit0(gHawkWfpEngine);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&gHawkActiveFilterBank, 0);
        InterlockedExchange(&gHawkWfpReady, 1);
        return STATUS_SUCCESS;
    }
Abort:
    FwpmTransactionAbort0(gHawkWfpEngine);
Failure:
    FwpmEngineClose0(gHawkWfpEngine);
    gHawkWfpEngine = NULL;
    InterlockedExchange(&gHawkActiveFilterBank, -1);
    return status;
}

static VOID NTAPI HawkBfeStateChanged(
    _Inout_opt_ VOID *context,
    _In_ FWPM_SERVICE_STATE newState
) {
    UNREFERENCED_PARAMETER(context);
    ExAcquireFastMutex(&gHawkWfpMutex);
    if (newState == FWPM_SERVICE_RUNNING) {
        (VOID)HawkAddWfpPolicyObjects();
    } else {
        InterlockedExchange(&gHawkWfpReady, 0);
        if (gHawkWfpEngine != NULL) {
            FwpmEngineClose0(gHawkWfpEngine);
            gHawkWfpEngine = NULL;
        }
        InterlockedExchange(&gHawkActiveFilterBank, -1);
    }
    ExReleaseFastMutex(&gHawkWfpMutex);
}

NTSTATUS HawkWfpReauthorizeFlows(VOID) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    ExAcquireFastMutex(&gHawkWfpMutex);
    const LONG activeBank = InterlockedCompareExchange(
        &gHawkActiveFilterBank,
        0,
        0
    );
    /*
     * Readiness is an externally reported health assertion, not a latch that
     * may permanently prevent repair. A failed atomic transaction leaves the
     * active bank unchanged, so the expiry retry path may attempt the inactive
     * bank again while health remains red.
     */
    if (gHawkWfpEngine == NULL ||
        (activeBank != 0 && activeBank != 1)) {
        ExReleaseFastMutex(&gHawkWfpMutex);
        return STATUS_DEVICE_NOT_READY;
    }
    const ULONG inactiveBank = activeBank == 0 ? 1U : 0U;
    NTSTATUS status = FwpmTransactionBegin0(gHawkWfpEngine, 0);
    if (!NT_SUCCESS(status)) goto Failure;
    status = HawkInstallFilterBank(inactiveBank);
    if (!NT_SUCCESS(status)) goto Abort;
    status = HawkDeleteFilterBank(activeBank);
    if (!NT_SUCCESS(status)) goto Abort;
    status = FwpmTransactionCommit0(gHawkWfpEngine);
    if (!NT_SUCCESS(status)) goto Failure;
    InterlockedExchange(&gHawkActiveFilterBank, (LONG)inactiveBank);
    InterlockedExchange(&gHawkWfpReady, 1);
    ExReleaseFastMutex(&gHawkWfpMutex);
    return STATUS_SUCCESS;

Abort:
    FwpmTransactionAbort0(gHawkWfpEngine);
Failure:
    /* A failed transition immediately removes the green health assertion. */
    InterlockedExchange(&gHawkWfpReady, 0);
    ExReleaseFastMutex(&gHawkWfpMutex);
    return status;
}

BOOLEAN HawkWfpReady(VOID) {
    return InterlockedCompareExchange(&gHawkWfpReady, 0, 0) != 0;
}

NTSTATUS HawkRegisterWfpCallouts(_In_ PDEVICE_OBJECT DeviceObject) {
    ExInitializeFastMutex(&gHawkWfpMutex);
    InterlockedExchange(&gHawkWfpReady, 0);
    InterlockedExchange(&gHawkActiveFilterBank, -1);
    FWPS_CALLOUT0 calloutV4 = {0};
    calloutV4.calloutKey = HAWK_CONNECT_V4_CALLOUT;
    calloutV4.classifyFn = HawkClassifyConnect;
    calloutV4.notifyFn = HawkNotify;
    calloutV4.flowDeleteFn = HawkFlowDelete;
    NTSTATUS status = FwpsCalloutRegister(DeviceObject, &calloutV4, &gHawkConnectV4CalloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    FWPS_CALLOUT0 calloutV6 = {0};
    calloutV6.calloutKey = HAWK_CONNECT_V6_CALLOUT;
    calloutV6.classifyFn = HawkClassifyConnect;
    calloutV6.notifyFn = HawkNotify;
    calloutV6.flowDeleteFn = HawkFlowDelete;
    status = FwpsCalloutRegister(DeviceObject, &calloutV6, &gHawkConnectV6CalloutId);
    if (!NT_SUCCESS(status)) {
        FwpsCalloutUnregisterById(gHawkConnectV4CalloutId);
        gHawkConnectV4CalloutId = 0;
        return status;
    }
    status = FwpmBfeStateSubscribeChanges0(
        DeviceObject,
        HawkBfeStateChanged,
        NULL,
        &gHawkBfeChangeHandle
    );
    if (!NT_SUCCESS(status)) {
        FwpsCalloutUnregisterById(gHawkConnectV6CalloutId);
        FwpsCalloutUnregisterById(gHawkConnectV4CalloutId);
        gHawkConnectV6CalloutId = 0;
        gHawkConnectV4CalloutId = 0;
        return status;
    }
    if (FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING) {
        ExAcquireFastMutex(&gHawkWfpMutex);
        status = HawkAddWfpPolicyObjects();
        ExReleaseFastMutex(&gHawkWfpMutex);
        if (!NT_SUCCESS(status)) {
            (VOID)FwpmBfeStateUnsubscribeChanges0(gHawkBfeChangeHandle);
            gHawkBfeChangeHandle = NULL;
            FwpsCalloutUnregisterById0(gHawkConnectV6CalloutId);
            FwpsCalloutUnregisterById0(gHawkConnectV4CalloutId);
            gHawkConnectV6CalloutId = 0;
            gHawkConnectV4CalloutId = 0;
        }
    }
    return status;
}

NTSTATUS HawkUnregisterWfpCallouts(VOID) {
    InterlockedExchange(&gHawkWfpReady, 0);
    InterlockedExchange(&gHawkActiveFilterBank, -1);
    if (gHawkBfeChangeHandle != NULL) {
        NTSTATUS status = FwpmBfeStateUnsubscribeChanges0(gHawkBfeChangeHandle);
        if (!NT_SUCCESS(status)) return status;
        gHawkBfeChangeHandle = NULL;
    }
    ExAcquireFastMutex(&gHawkWfpMutex);
    if (gHawkWfpEngine != NULL) {
        FwpmEngineClose0(gHawkWfpEngine);
        gHawkWfpEngine = NULL;
    }
    ExReleaseFastMutex(&gHawkWfpMutex);
    if (gHawkConnectV4CalloutId != 0) {
        NTSTATUS status = FwpsCalloutUnregisterById0(gHawkConnectV4CalloutId);
        if (!NT_SUCCESS(status)) return status;
        gHawkConnectV4CalloutId = 0;
    }
    if (gHawkConnectV6CalloutId != 0) {
        NTSTATUS status = FwpsCalloutUnregisterById0(gHawkConnectV6CalloutId);
        if (!NT_SUCCESS(status)) return status;
        gHawkConnectV6CalloutId = 0;
    }
    return STATUS_SUCCESS;
}

// Dynamic filters are installed by this signed driver at both
// FWPM_LAYER_ALE_AUTH_CONNECT_V4 and FWPM_LAYER_ALE_AUTH_CONNECT_V6. UDP/QUIC
// and direct-IP routes therefore cross the same local policy boundary.
