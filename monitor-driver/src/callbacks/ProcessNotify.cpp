#include <ntddk.h>
#include "ProcessNotify.hpp"
#include "../ipc/DeviceControl.hpp"
#include "../shared/KernelTypes.hpp"

static VOID OnProcessNotify(
    PEPROCESS Process,
    HANDLE    ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KernelEvent ev{};
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&ev.timestampMs);
    ev.timestampMs /= 10000;
    ev.targetPid    = HandleToULong(ProcessId);
    ev.callerPid    = HandleToULong(PsGetCurrentProcessId());
    ev.isRemote     = FALSE;

    if (CreateInfo) {
        ev.kind = KernelEventKind::ProcessCreate;
        if (CreateInfo->ImageFileName) {
            RtlCopyMemory(ev.imagePath,
                          CreateInfo->ImageFileName->Buffer,
                          min(CreateInfo->ImageFileName->Length,
                              (USHORT)(sizeof(ev.imagePath) - sizeof(WCHAR))));
        }
    } else {
        ev.kind = KernelEventKind::ProcessTerminate;
    }

    UNREFERENCED_PARAMETER(Process);
    DeviceControl::Enqueue(ev);
}

NTSTATUS ProcessNotify::Register() {
    return PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
}

void ProcessNotify::Unregister() {
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
}
