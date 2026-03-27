#pragma once
#include <cstdint>

enum class ApiType : uint8_t {
    OpenProcess         = 0,
    ReadProcessMemory   = 1,
    WriteProcessMemory  = 2,
    VirtualAllocEx      = 3,
    CreateRemoteThread  = 4,
    NtOpenProcess       = 5,
    NtReadVirtualMemory = 6,
    NtWriteVirtualMemory= 7,
    NtAllocateVirtual   = 8,
    NtCreateThreadEx    = 9,
};

enum class Severity : uint8_t {
    Info     = 0,
    Warning  = 1,
    Critical = 2,
};

enum class CallOrigin : uint8_t {
    Api      = 0,
    NtLayer  = 1,
    Direct   = 2,
};

struct ProcessEvent {
    uint64_t   id;
    uint64_t   timestampMs;
    ApiType    api;
    Severity   severity;
    CallOrigin origin;
    uint32_t   callerPid;
    char       callerName[260];
    uint32_t   targetPid;
    char       targetName[260];
    uint64_t   param1;
    uint64_t   param2;
    uint64_t   param3;
    uint64_t   returnValue;
    bool       success;
    bool       suspiciousCaller;
};

enum class HwEventType : uint8_t {
    PciDeviceScan    = 0,
    DmaDeviceFound   = 1,
    FirmwareAnomaly  = 2,
    SignatureCheck   = 3,
    IommuStatus      = 4,
};

enum class ThreatLevel : uint8_t {
    Safe       = 0,
    Suspicious = 1,
    Dangerous  = 2,
};

struct HardwareEvent {
    uint64_t    id;
    uint64_t    timestampMs;
    HwEventType type;
    Severity    severity;
    ThreatLevel threat;
    char        deviceName[260];
    char        detail[512];
    uint16_t    vendorId;
    uint16_t    deviceId;
    uint16_t    subVendorId;
    uint16_t    subDeviceId;
    char        location[260];
    bool        flagged;
};

inline const char* HwEventTypeName(HwEventType t) {
    switch (t) {
        case HwEventType::PciDeviceScan:  return "PciDeviceScan";
        case HwEventType::DmaDeviceFound: return "DmaDeviceFound";
        case HwEventType::FirmwareAnomaly:return "FirmwareAnomaly";
        case HwEventType::SignatureCheck: return "SignatureCheck";
        case HwEventType::IommuStatus:    return "IommuStatus";
        default:                          return "Unknown";
    }
}

inline const char* ThreatLevelName(ThreatLevel t) {
    switch (t) {
        case ThreatLevel::Safe:       return "safe";
        case ThreatLevel::Suspicious: return "suspicious";
        case ThreatLevel::Dangerous:  return "dangerous";
        default:                      return "safe";
    }
}

inline const char* ApiTypeName(ApiType t) {
    switch (t) {
        case ApiType::OpenProcess:          return "OpenProcess";
        case ApiType::ReadProcessMemory:    return "ReadProcessMemory";
        case ApiType::WriteProcessMemory:   return "WriteProcessMemory";
        case ApiType::VirtualAllocEx:       return "VirtualAllocEx";
        case ApiType::CreateRemoteThread:   return "CreateRemoteThread";
        case ApiType::NtOpenProcess:        return "NtOpenProcess";
        case ApiType::NtReadVirtualMemory:  return "NtReadVirtualMemory";
        case ApiType::NtWriteVirtualMemory: return "NtWriteVirtualMemory";
        case ApiType::NtAllocateVirtual:    return "NtAllocateVirtualMemory";
        case ApiType::NtCreateThreadEx:     return "NtCreateThreadEx";
        default:                            return "Unknown";
    }
}

inline const char* SeverityName(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Warning:  return "warning";
        case Severity::Critical: return "critical";
        default:                 return "info";
    }
}

inline const char* OriginName(CallOrigin o) {
    switch (o) {
        case CallOrigin::Api:     return "api";
        case CallOrigin::NtLayer: return "nt";
        case CallOrigin::Direct:  return "direct";
        default:                  return "api";
    }
}

inline Severity ClassifySeverity(ApiType api, uint64_t access) {
    switch (api) {
        case ApiType::WriteProcessMemory:
        case ApiType::NtWriteVirtualMemory:
        case ApiType::CreateRemoteThread:
        case ApiType::NtCreateThreadEx:
            return Severity::Critical;

        case ApiType::VirtualAllocEx:
        case ApiType::NtAllocateVirtual:
            return Severity::Warning;

        case ApiType::ReadProcessMemory:
        case ApiType::NtReadVirtualMemory:
            return Severity::Warning;

        case ApiType::OpenProcess:
        case ApiType::NtOpenProcess: {
            if ((access & 0x001F0FFF) == 0x001F0FFF) return Severity::Critical;
            if ((access & 0x0028) == 0x0028)         return Severity::Critical;
            if (access & 0x0002)                     return Severity::Critical;
            if ((access & 0x0008) != 0 || (access & 0x0020) != 0) return Severity::Warning;
            if ((access & 0x0010) != 0)              return Severity::Info;
            return Severity::Info;
        }

        default:
            return Severity::Info;
    }
}
