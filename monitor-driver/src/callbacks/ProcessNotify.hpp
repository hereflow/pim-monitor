#pragma once
#include <ntddk.h>

namespace ProcessNotify {
    NTSTATUS Register();
    void     Unregister();
}
