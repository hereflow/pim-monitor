#include <ntddk.h>
#include "ObCallbacks.hpp"
#include "../ipc/DeviceControl.hpp"
#include "../shared/KernelTypes.hpp"

static PVOID g_regHandle = nullptr;

static OB_PREOP_CALLBACK_STATUS PreOpenProcess(
    PVOID, POB_PRE_OPERATION_INFORMATION OpInfo)
{
    if (OpInfo->KernelHandle) return OB_PREOP_SUCCESS;

    PEPROCESS target = (PEPROCESS)OpInfo->Object;
    HANDLE    targetPid = PsGetProcessId(target);
    HANDLE    callerPid = PsGetCurrentProcessId();

    if (targetPid == callerPid) return OB_PREOP_SUCCESS;

    KernelEvent ev{};
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&ev.timestampMs);
    ev.timestampMs  /= 10000;
    ev.callerPid     = HandleToULong(callerPid);
    ev.targetPid     = HandleToULong(targetPid);
    ev.grantedAccess = OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
    ev.kind          = KernelEventKind::ProcessOpen;
    ev.isRemote      = TRUE;

    PUNICODE_STRING imageName = nullptr;
    if (NT_SUCCESS(SeLocateProcessImageName(target, &imageName)) && imageName) {
        RtlCopyMemory(ev.imagePath, imageName->Buffer,
                      min(imageName->Length, (USHORT)(sizeof(ev.imagePath) - sizeof(WCHAR))));
        ExFreePool(imageName);
    }

    DeviceControl::Enqueue(ev);
    return OB_PREOP_SUCCESS;
}

NTSTATUS ObCallbacks::Register() {
    OB_OPERATION_REGISTRATION opReg{};
    opReg.ObjectType            = PsProcessType;
    opReg.Operations            = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation          = PreOpenProcess;
    opReg.PostOperation         = nullptr;

    OB_CALLBACK_REGISTRATION reg{};
    reg.Version                 = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&reg.Altitude, L"380010");
    reg.RegistrationContext     = nullptr;
    reg.OperationRegistration   = &opReg;

    return ObRegisterCallbacks(&reg, &g_regHandle);
}

void ObCallbacks::Unregister() {
    if (g_regHandle) {
        ObUnRegisterCallbacks(g_regHandle);
        g_regHandle = nullptr;
    }
}
