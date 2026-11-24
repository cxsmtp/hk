#include <ntddk.h>
#include "../include/HawkKernelPolicy.h"

static VOID HawkProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo == NULL) {
        HawkForgetProcessIdentity(ProcessId);
        return;
    }
    PUNICODE_STRING locatedImageName = NULL;
    PCUNICODE_STRING imageName = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &locatedImageName)) &&
        locatedImageName != NULL && locatedImageName->Length > 0) {
        imageName = locatedImageName;
    } else if (CreateInfo->FileOpenNameAvailable &&
        CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Length > 0) {
        imageName = CreateInfo->ImageFileName;
    }
    HawkProcessLineageSeed targetIdentity;
    RtlZeroMemory(&targetIdentity, sizeof(targetIdentity));
    const HawkKernelDecision decision = HawkFloorEvaluateProcess(
        Process,
        ProcessId,
        CreateInfo,
        imageName,
        &targetIdentity
    );
    if (decision != HawkKernelAllow) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        RtlSecureZeroMemory(&targetIdentity, sizeof(targetIdentity));
        if (locatedImageName != NULL) ExFreePool(locatedImageName);
        return;
    }
    RtlSecureZeroMemory(&targetIdentity, sizeof(targetIdentity));
    if (locatedImageName != NULL) ExFreePool(locatedImageName);
}

NTSTATUS HawkRegisterProcessControl(VOID) {
    return PsSetCreateProcessNotifyRoutineEx(HawkProcessNotify, FALSE);
}

NTSTATUS HawkUnregisterProcessControl(VOID) {
    return PsSetCreateProcessNotifyRoutineEx(HawkProcessNotify, TRUE);
}
