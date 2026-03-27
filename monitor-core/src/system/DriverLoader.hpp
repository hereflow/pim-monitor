#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <cstdint>

class DriverLoader {
public:
    static DriverLoader& Instance();

    bool Load();
    void Unload();
    void StartPolling();
    void StopPolling();
    bool IsLoaded() const;

private:
    DriverLoader() = default;
    ~DriverLoader();

    static constexpr const char* kServiceName = "ProcMonitorDrv";
    static constexpr const char* kDisplayName = "Process Integrity Monitor Driver";
    static constexpr const wchar_t* kDevicePath = L"\\\\.\\ProcMonitor";

    #pragma pack(push, 1)
    struct KernelEvent {
        uint64_t timestampMs;
        uint32_t callerPid;
        uint32_t targetPid;
        uint32_t grantedAccess;
        uint8_t  kind;
        uint8_t  isRemote;
        wchar_t  imagePath[260];
    };
    #pragma pack(pop)

    enum KernelEventKind : uint8_t {
        ProcessOpen      = 0,
        ProcessCreate    = 1,
        ProcessTerminate = 2,
        ThreadCreate     = 3,
    };

    bool IsAdmin() const;
    bool IsTestSigningEnabled() const;
    std::string FindDriverPath() const;

    bool ServiceExists() const;
    bool ServiceIsRunning() const;
    bool SvcInstall(const std::string& sysPath);
    bool SvcStart();
    bool SvcStop();
    bool SvcRemove();
    bool WaitForServiceState(uint32_t desiredState, uint32_t timeoutMs) const;

    bool OpenDevice();
    void CloseDevice();
    void PollLoop();
    void ProcessKernelEvent(const KernelEvent& kev);

    HANDLE             device_{ INVALID_HANDLE_VALUE };
    std::thread        pollThread_;
    std::atomic<bool>  polling_{ false };
    std::atomic<bool>  loaded_{ false };
    bool               ownedService_{ false };
};
