#pragma once
#include <ntddk.h>

#define DRIVER_DEVICE_NAME  L"\\Device\\ProcMonitor"
#define DRIVER_SYMLINK_NAME L"\\DosDevices\\ProcMonitor"

#define IOCTL_GET_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define RING_CAPACITY 4096

enum class KernelEventKind : UINT8 {
    ProcessOpen     = 0,
    ProcessCreate   = 1,
    ProcessTerminate= 2,
    ThreadCreate    = 3,
};

#pragma pack(push, 1)
struct KernelEvent {
    UINT64        timestampMs;
    UINT32        callerPid;
    UINT32        targetPid;
    UINT32        grantedAccess;
    KernelEventKind kind;
    BOOLEAN       isRemote;
    WCHAR         imagePath[260];
};
#pragma pack(pop)

struct EventRing {
    volatile LONG head;
    volatile LONG tail;
    KernelEvent   records[RING_CAPACITY];
};
