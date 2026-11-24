#include <ntddk.h>
#include <wdmsec.h>

#include "../include/HawkKernelControl.h"
#include "../include/HawkKernelPolicy.h"

static PDEVICE_OBJECT gHawkControlDevice = NULL;
static UNICODE_STRING gHawkSymbolicLink;
static EX_RUNDOWN_REF gHawkControlRundown;
static volatile LONG gHawkControlStopping = 0;
static const GUID HAWK_CONTROL_DEVICE_CLASS =
    {0x5e8dbe1c, 0x52d8, 0x49a9, {0x91, 0x94, 0x3d, 0xc3, 0xa0, 0x0d, 0x71, 0x5f}};

static NTSTATUS HawkCompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS HawkCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    if (InterlockedCompareExchange(&gHawkControlStopping, 0, 0) != 0 ||
        !ExAcquireRundownProtection(&gHawkControlRundown)) {
        return HawkCompleteIrp(irp, STATUS_DELETE_PENDING, 0);
    }
    const NTSTATUS status = HawkCompleteIrp(irp, STATUS_SUCCESS, 0);
    ExReleaseRundownProtection(&gHawkControlRundown);
    return status;
}

static NTSTATUS HawkDeviceControlCore(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inputBytes = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outputBytes = stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (code == IOCTL_HAWK_POLICY_REPLACE) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(irp, FILE_WRITE_DATA))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        if (inputBytes < FIELD_OFFSET(HawkWindowsPolicyEnvelope, rules) ||
            inputBytes > HAWK_WINDOWS_MAX_POLICY_BYTES || irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
        }
        const HawkWindowsPolicyEnvelope *envelope = irp->AssociatedIrp.SystemBuffer;
        if (envelope->signatureVerified != 1 || envelope->configurationIntegrityValid != 1) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        return HawkCompleteIrp(
            irp,
            HawkFloorPublishSnapshot(envelope, inputBytes),
            0
        );
    }
    if (code == IOCTL_HAWK_POLICY_ARM) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(irp, FILE_WRITE_DATA))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        if (inputBytes != sizeof(HawkWindowsArmRequest) || irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
        }
        const HawkWindowsArmRequest *request = irp->AssociatedIrp.SystemBuffer;
        if (request->version != HAWK_WINDOWS_POLICY_VERSION || request->armed > 1) {
            return HawkCompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
        }
        if (request->reserved[0] != 0 || request->reserved[1] != 0 ||
            request->reserved[2] != 0) {
            return HawkCompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
        }
        return HawkCompleteIrp(
            irp,
            HawkSetPolicyArmed(request->armed != 0, request->expectedGeneration),
            0
        );
    }
    if (code == IOCTL_HAWK_POLICY_STATUS) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(irp, FILE_READ_DATA))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        if (outputBytes < sizeof(HawkWindowsPolicyStatus) || irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        HawkGetPolicyStatus((HawkWindowsPolicyStatus *)irp->AssociatedIrp.SystemBuffer);
        return HawkCompleteIrp(irp, STATUS_SUCCESS, sizeof(HawkWindowsPolicyStatus));
    }
    if (code == IOCTL_HAWK_PROCESS_SEED) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(irp, FILE_WRITE_DATA))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        const ULONG headerBytes = FIELD_OFFSET(HawkWindowsProcessSeedRequest, processes);
        if (inputBytes < headerBytes || irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
        }
        const HawkWindowsProcessSeedRequest *request = irp->AssociatedIrp.SystemBuffer;
        if (request->version != HAWK_WINDOWS_PROCESS_SEED_VERSION ||
            request->processCount == 0 ||
            request->processCount > HAWK_WINDOWS_MAX_PROCESS_SEED_COUNT ||
            inputBytes != headerBytes + request->processCount *
                sizeof(HawkWindowsProcessSeedEntry)) {
            return HawkCompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
        }
        return HawkCompleteIrp(
            irp,
            HawkSeedProcessIdentities(request->processes, request->processCount),
            0
        );
    }
    if (code == IOCTL_HAWK_PERMITS_REPLACE) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(irp, FILE_WRITE_DATA))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        const ULONG headerBytes = FIELD_OFFSET(HawkWindowsPermitEnvelope, permits);
        if (inputBytes < headerBytes ||
            inputBytes > HAWK_WINDOWS_MAX_PERMIT_BYTES ||
            irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
        }
        const HawkWindowsPermitEnvelope *envelope =
            irp->AssociatedIrp.SystemBuffer;
        if (envelope->brokerAuthenticated != 1 ||
            envelope->configurationIntegrityValid != 1) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        return HawkCompleteIrp(
            irp,
            HawkFloorPublishPermits(envelope, inputBytes),
            0
        );
    }
    if (code == IOCTL_HAWK_PROCESS_IDENTITY_QUERY) {
        if (!NT_SUCCESS(IoValidateDeviceIoControlAccess(
                irp,
                FILE_READ_DATA | FILE_WRITE_DATA
            ))) {
            return HawkCompleteIrp(irp, STATUS_ACCESS_DENIED, 0);
        }
        if (inputBytes != sizeof(HawkWindowsProcessIdentityQuery) ||
            outputBytes < sizeof(HawkWindowsProcessIdentityResponse) ||
            irp->AssociatedIrp.SystemBuffer == NULL) {
            return HawkCompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
        }
        const HawkWindowsProcessIdentityQuery query =
            *(const HawkWindowsProcessIdentityQuery *)
                irp->AssociatedIrp.SystemBuffer;
        if (query.version != HAWK_WINDOWS_POLICY_VERSION ||
            query.reserved != 0 || query.processId == 0) {
            return HawkCompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
        }
        HawkWindowsProcessIdentityResponse *response =
            irp->AssociatedIrp.SystemBuffer;
        const NTSTATUS status = HawkQueryProcessIdentity(
            query.processId,
            response
        );
        return HawkCompleteIrp(
            irp,
            status,
            NT_SUCCESS(status) ? sizeof(*response) : 0
        );
    }
    return HawkCompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS HawkDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    if (InterlockedCompareExchange(&gHawkControlStopping, 0, 0) != 0 ||
        !ExAcquireRundownProtection(&gHawkControlRundown)) {
        return HawkCompleteIrp(irp, STATUS_DELETE_PENDING, 0);
    }
    const NTSTATUS status = HawkDeviceControlCore(deviceObject, irp);
    ExReleaseRundownProtection(&gHawkControlRundown);
    return status;
}

NTSTATUS HawkInitializeKernelControl(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT *deviceObject) {
    UNICODE_STRING deviceName;
    UNICODE_STRING sddl;
    RtlInitUnicodeString(&deviceName, L"\\Device\\HawkEndpointFloor");
    ExInitializeRundownProtection(&gHawkControlRundown);
    InterlockedExchange(&gHawkControlStopping, 0);
    RtlInitUnicodeString(&gHawkSymbolicLink, L"\\DosDevices\\HawkEndpointFloor");
    /*
     * The unrestricted Hawk service SID can mutate policy. Administrators can
     * inspect bounded status; an unrelated LocalSystem process cannot publish
     * a forged signatureVerified envelope.
     */
    RtlInitUnicodeString(
        &sddl,
        L"D:P(A;;GA;;;S-1-5-80-1135535808-2200536610-2577844612-1285382279-175032405)"
        L"(A;;GR;;;BA)"
    );
    NTSTATUS status = IoCreateDeviceSecure(
        driverObject,
        0,
        &deviceName,
        HAWK_WINDOWS_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &sddl,
        &HAWK_CONTROL_DEVICE_CLASS,
        &gHawkControlDevice
    );
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&gHawkSymbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gHawkControlDevice);
        gHawkControlDevice = NULL;
        return status;
    }
    driverObject->MajorFunction[IRP_MJ_CREATE] = HawkCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = HawkCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = HawkCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HawkDeviceControl;
    gHawkControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    *deviceObject = gHawkControlDevice;
    return STATUS_SUCCESS;
}

VOID HawkShutdownKernelControl(VOID) {
    if (gHawkControlDevice != NULL) {
        InterlockedExchange(&gHawkControlStopping, 1);
        ExWaitForRundownProtectionRelease(&gHawkControlRundown);
        IoDeleteSymbolicLink(&gHawkSymbolicLink);
        IoDeleteDevice(gHawkControlDevice);
        gHawkControlDevice = NULL;
    }
}

PDEVICE_OBJECT HawkGetKernelControlDeviceObject(VOID) {
    return gHawkControlDevice;
}
