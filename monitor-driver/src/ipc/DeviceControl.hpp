#pragma once
#include <ntddk.h>
#include "../shared/KernelTypes.hpp"

namespace DeviceControl {
    void Enqueue(const KernelEvent& ev);

    NTSTATUS DispatchCreate (PDEVICE_OBJECT, PIRP irp);
    NTSTATUS DispatchClose  (PDEVICE_OBJECT, PIRP irp);
    NTSTATUS DispatchControl(PDEVICE_OBJECT, PIRP irp);
}
