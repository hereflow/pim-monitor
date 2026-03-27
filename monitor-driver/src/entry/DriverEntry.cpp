#include <ntddk.h>
#include "../callbacks/ObCallbacks.hpp"
#include "../callbacks/ProcessNotify.hpp"
#include "../ipc/DeviceControl.hpp"

extern "C" NTSTATUS InitDeviceControl(PDRIVER_OBJECT);
extern "C" void     CleanupDeviceControl(PDRIVER_OBJECT);

static PDRIVER_OBJECT g_driver = nullptr;

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    ObCallbacks::Unregister();
    ProcessNotify::Unregister();
    CleanupDeviceControl(DriverObject);
    DbgPrint("[ProcMonitor] Unloaded.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
    g_driver = DriverObject;
    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceControl::DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceControl::DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl::DispatchControl;

    NTSTATUS status = InitDeviceControl(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcMonitor] Device init failed: 0x%08X\n", status);
        return status;
    }

    status = ObCallbacks::Register();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcMonitor] ObCallbacks failed: 0x%08X\n", status);
        CleanupDeviceControl(DriverObject);
        return status;
    }

    status = ProcessNotify::Register();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcMonitor] ProcessNotify failed: 0x%08X\n", status);
        ObCallbacks::Unregister();
        CleanupDeviceControl(DriverObject);
        return status;
    }

    DbgPrint("[ProcMonitor] Loaded — ObCallbacks + ProcessNotify active.\n");
    return STATUS_SUCCESS;
}
