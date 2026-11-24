#include <fltKernel.h>
#include "../include/HawkKernelPolicy.h"
#include "../include/HawkKernelControl.h"

NTSTATUS HawkRegisterProcessControl(VOID);
NTSTATUS HawkUnregisterProcessControl(VOID);
NTSTATUS HawkRegisterWfpCallouts(_In_ PDEVICE_OBJECT DeviceObject);
NTSTATUS HawkUnregisterWfpCallouts(VOID);

PFLT_FILTER gHawkFilter = NULL;

static FLT_PREOP_CALLBACK_STATUS HawkPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(CompletionContext);
    /*
     * This floor governs user applications by canonical binary identity.
     * Kernel-originated and paging/delegated operations cannot be attributed
     * to that user binary safely and must not be converted into an unknown-PID
     * system-wide denial.
     */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    switch (Data->Iopb->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_READ:
        case IRP_MJ_WRITE:
        case IRP_MJ_SET_INFORMATION:
        case IRP_MJ_SET_EA:
        case IRP_MJ_FILE_SYSTEM_CONTROL:
        case IRP_MJ_DIRECTORY_CONTROL:
        case IRP_MJ_QUERY_INFORMATION:
        case IRP_MJ_SET_SECURITY:
            break;
        default:
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    const HawkKernelDecision decision = HawkFloorEvaluateFile(Data, FltObjects);
    if (decision != HawkKernelAllow) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS HawkUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    HawkSetPolicyArmed(FALSE, 0);
    NTSTATUS status = HawkUnregisterWfpCallouts();
    if (!NT_SUCCESS(status)) return status;
    status = HawkUnregisterProcessControl();
    if (!NT_SUCCESS(status)) return status;
    if (gHawkFilter != NULL) {
        FltUnregisterFilter(gHawkFilter);
        gHawkFilter = NULL;
    }
    HawkShutdownKernelControl();
    HawkShutdownKernelPolicy();
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION gHawkCallbacks[] = {
    {IRP_MJ_CREATE, 0, HawkPreOperation, NULL},
    {IRP_MJ_READ, 0, HawkPreOperation, NULL},
    {IRP_MJ_WRITE, 0, HawkPreOperation, NULL},
    {IRP_MJ_SET_INFORMATION, 0, HawkPreOperation, NULL},
    {IRP_MJ_SET_EA, 0, HawkPreOperation, NULL},
    {IRP_MJ_FILE_SYSTEM_CONTROL, 0, HawkPreOperation, NULL},
    {IRP_MJ_DIRECTORY_CONTROL, 0, HawkPreOperation, NULL},
    {IRP_MJ_QUERY_INFORMATION, 0, HawkPreOperation, NULL},
    {IRP_MJ_SET_SECURITY, 0, HawkPreOperation, NULL},
    {IRP_MJ_OPERATION_END}
};

static const FLT_REGISTRATION gHawkRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gHawkCallbacks,
    HawkUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    PDEVICE_OBJECT controlDevice = NULL;
    NTSTATUS status = HawkInitializeKernelPolicy();
    if (!NT_SUCCESS(status)) return status;
    status = HawkInitializeKernelControl(DriverObject, &controlDevice);
    if (!NT_SUCCESS(status)) goto PolicyFailure;
    status = HawkRegisterProcessControl();
    if (!NT_SUCCESS(status)) goto ControlFailure;
    status = HawkRegisterWfpCallouts(controlDevice);
    if (!NT_SUCCESS(status)) goto ProcessFailure;
    status = FltRegisterFilter(DriverObject, &gHawkRegistration, &gHawkFilter);
    if (!NT_SUCCESS(status)) {
        goto WfpFailure;
    }
    status = FltStartFiltering(gHawkFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gHawkFilter);
        gHawkFilter = NULL;
        goto WfpFailure;
    }
    return status;

WfpFailure:
    (VOID)HawkUnregisterWfpCallouts();
ProcessFailure:
    (VOID)HawkUnregisterProcessControl();
ControlFailure:
    HawkShutdownKernelControl();
PolicyFailure:
    HawkShutdownKernelPolicy();
    return status;
}
