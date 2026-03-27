#include <ntddk.h>
#include "DeviceControl.hpp"
#include "../shared/KernelTypes.hpp"

static EventRing* g_ring  = nullptr;
static KSPIN_LOCK g_lock;

static ULONG64 GetTimestampMs() {
    LARGE_INTEGER t;
    KeQuerySystemTimePrecise(&t);
    return (ULONG64)t.QuadPart / 10000;
}

NTSTATUS DeviceControl::DispatchCreate(PDEVICE_OBJECT, PIRP irp) {
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl::DispatchClose(PDEVICE_OBJECT, PIRP irp) {
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl::DispatchControl(PDEVICE_OBJECT, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code != IOCTL_GET_EVENTS) {
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!g_ring) {
        irp->IoStatus.Status      = STATUS_INSUFFICIENT_RESOURCES;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG outLen  = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outBuf  = irp->AssociatedIrp.SystemBuffer;
    ULONG written = 0;
    ULONG maxEvs  = outLen / sizeof(KernelEvent);

    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);

    while (written < maxEvs) {
        LONG head = g_ring->head;
        LONG tail = g_ring->tail;
        if (head == tail) break;

        RtlCopyMemory(
            (PUCHAR)outBuf + written * sizeof(KernelEvent),
            &g_ring->records[head % RING_CAPACITY],
            sizeof(KernelEvent));

        InterlockedIncrement(&g_ring->head);
        written++;
    }

    KeReleaseSpinLock(&g_lock, irql);

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = written * sizeof(KernelEvent);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

void DeviceControl::Enqueue(const KernelEvent& ev) {
    if (!g_ring) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);

    LONG tail = g_ring->tail;
    g_ring->records[tail % RING_CAPACITY] = ev;
    InterlockedIncrement(&g_ring->tail);

    if (g_ring->tail - g_ring->head >= RING_CAPACITY)
        InterlockedIncrement(&g_ring->head);

    KeReleaseSpinLock(&g_lock, irql);
}

extern "C" NTSTATUS InitDeviceControl(PDRIVER_OBJECT DriverObject) {
    g_ring = (EventRing*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EventRing), 'PMon');
    if (!g_ring) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_ring, sizeof(EventRing));
    KeInitializeSpinLock(&g_lock);

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DRIVER_DEVICE_NAME);

    PDEVICE_OBJECT devObj = nullptr;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        ExFreePool(g_ring);
        g_ring = nullptr;
        return status;
    }

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, DRIVER_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        ExFreePool(g_ring);
        g_ring = nullptr;
    }

    return status;
}

extern "C" void CleanupDeviceControl(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, DRIVER_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    if (g_ring) {
        ExFreePool(g_ring);
        g_ring = nullptr;
    }
}
