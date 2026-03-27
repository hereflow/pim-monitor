#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <mutex>
#include <nlohmann/json.hpp>
#include "../core/EventTypes.hpp"

constexpr const char* kPipeName = "\\\\.\\pipe\\proc-monitor";

inline void to_json(nlohmann::json& j, const ProcessEvent& e) {
    j = {
        { "type",             "process"                },
        { "id",               e.id                     },
        { "ts",               e.timestampMs            },
        { "api",              ApiTypeName(e.api)       },
        { "severity",         SeverityName(e.severity) },
        { "origin",           OriginName(e.origin)     },
        { "suspiciousCaller", e.suspiciousCaller       },
        { "callerPid",        e.callerPid              },
        { "callerName",       e.callerName             },
        { "targetPid",        e.targetPid              },
        { "targetName",       e.targetName             },
        { "param1",           e.param1                 },
        { "param2",           e.param2                 },
        { "param3",           e.param3                 },
        { "returnValue",      e.returnValue            },
        { "success",          e.success                },
    };
}

inline void to_json(nlohmann::json& j, const HardwareEvent& e) {
    j = {
        { "type",        "hardware"                     },
        { "id",          e.id                           },
        { "ts",          e.timestampMs                  },
        { "hwType",      HwEventTypeName(e.type)        },
        { "severity",    SeverityName(e.severity)       },
        { "threat",      ThreatLevelName(e.threat)      },
        { "deviceName",  e.deviceName                   },
        { "detail",      e.detail                       },
        { "vendorId",    e.vendorId                     },
        { "deviceId",    e.deviceId                     },
        { "subVendorId", e.subVendorId                  },
        { "subDeviceId", e.subDeviceId                  },
        { "location",    e.location                     },
        { "flagged",     e.flagged                      },
    };
}

class PipeClient {
public:
    static PipeClient& Instance() {
        static PipeClient inst;
        return inst;
    }

    void Connect() {
        std::lock_guard<std::mutex> lock(mutex_);
        TryOpen();
    }

    void Send(const ProcessEvent& ev) {
        WriteJson(nlohmann::json(ev));
    }

    void SendHardware(const HardwareEvent& ev) {
        WriteJson(nlohmann::json(ev));
    }

    void Disconnect() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    PipeClient() : pipe_(INVALID_HANDLE_VALUE) {}
    ~PipeClient() { Disconnect(); }

    void WriteJson(const nlohmann::json& j) {
        std::string payload = j.dump() + '\n';

        std::lock_guard<std::mutex> lock(mutex_);
        if (pipe_ == INVALID_HANDLE_VALUE) {
            TryOpen();
            if (pipe_ == INVALID_HANDLE_VALUE) return;
        }

        DWORD written = 0;
        if (!WriteFile(pipe_, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr)) {
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void TryOpen() {
        if (pipe_ != INVALID_HANDLE_VALUE) return;
        pipe_ = CreateFileA(kPipeName, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe_ == INVALID_HANDLE_VALUE) return;
        DWORD mode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(pipe_, &mode, nullptr, nullptr);
    }

    HANDLE     pipe_;
    std::mutex mutex_;
};
