#pragma once
#include <ntddk.h>

namespace ObCallbacks {
    NTSTATUS Register();
    void     Unregister();
}
