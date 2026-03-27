#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace Nt {

using NTSTATUS = LONG;

struct UnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct ObjectAttributes {
    ULONG         Length;
    HANDLE        RootDirectory;
    UnicodeString* ObjectName;
    ULONG         Attributes;
    PVOID         SecurityDescriptor;
    PVOID         SecurityQualityOfService;
};

struct ClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

using FnNtOpenProcess = NTSTATUS(NTAPI*)(
    PHANDLE           ProcessHandle,
    ACCESS_MASK       DesiredAccess,
    ObjectAttributes* ObjAttr,
    ClientId*         ClientId
);

using FnNtReadVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

using FnNtWriteVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

using FnNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

using FnNtCreateThreadEx = NTSTATUS(NTAPI*)(
    PHANDLE           ThreadHandle,
    ACCESS_MASK       DesiredAccess,
    ObjectAttributes* ObjAttr,
    HANDLE            ProcessHandle,
    PVOID             StartRoutine,
    PVOID             Argument,
    ULONG             CreateFlags,
    SIZE_T            ZeroBits,
    SIZE_T            StackSize,
    SIZE_T            MaximumStackSize,
    PVOID             AttributeList
);

}
