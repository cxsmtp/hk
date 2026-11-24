#ifndef HAWK_KERNEL_CONTROL_H
#define HAWK_KERNEL_CONTROL_H

#include <ntddk.h>

NTSTATUS HawkInitializeKernelControl(
    _In_ PDRIVER_OBJECT DriverObject,
    _Outptr_ PDEVICE_OBJECT *DeviceObject
);
VOID HawkShutdownKernelControl(VOID);
PDEVICE_OBJECT HawkGetKernelControlDeviceObject(VOID);

#endif
