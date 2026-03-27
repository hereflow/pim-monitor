#include "pch.hpp"
#include "DriverLoader.hpp"
#include "ProcessCache.hpp"
#include "../core/EventTypes.hpp"
#include "../core/HookGuard.hpp"
#include "../domain/TrustedProcesses.hpp"
#include "../ipc/PipeClient.hpp"
#include "../console/Console.hpp"

#include <winioctl.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

struct SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

#define IOCTL_GET_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

static std::atomic<uint64_t> g_drvId{ 200000 };

DriverLoader& DriverLoader::Instance() {
    static DriverLoader inst;
    return inst;
}

DriverLoader::~DriverLoader() {
    Unload();
}

bool DriverLoader::IsLoaded() const {
    return loaded_;
}

bool DriverLoader::IsAdmin() const {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool DriverLoader::IsTestSigningEnabled() const {
    HKEY hKey = nullptr;
    bool enabled = false;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val);
        if (RegQueryValueExA(hKey, "UMCIAuditMode", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS) {
            if (val) enabled = true;
        }
        RegCloseKey(hKey);
    }

    SYSTEM_CODEINTEGRITY_INFORMATION sci{};
    sci.Length = sizeof(sci);
    using FnNtQuerySystemInformation = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto NtQuery = reinterpret_cast<FnNtQuerySystemInformation>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

    if (NtQuery) {
        if (NtQuery(103, &sci, sizeof(sci), nullptr) >= 0) {
            if (sci.CodeIntegrityOptions & 0x02)
                enabled = true;
        }
    }

    return enabled;
}

std::string DriverLoader::FindDriverPath() const {
    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';

    std::string candidates[] = {
        std::string(exePath) + "monitor-driver.sys",
        std::string(exePath) + "..\\monitor-driver\\build\\Debug\\monitor-driver.sys",
        std::string(exePath) + "..\\monitor-driver\\build\\Release\\monitor-driver.sys",
        std::string(exePath) + "..\\..\\monitor-driver\\build\\Debug\\monitor-driver.sys",
        std::string(exePath) + "..\\..\\monitor-driver\\build\\Release\\monitor-driver.sys",
    };

    for (const auto& path : candidates) {
        if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            return path;
    }

    return {};
}

bool DriverLoader::ServiceExists() const {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_QUERY_STATUS);
    bool exists = (svc != nullptr);

    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return exists;
}

bool DriverLoader::ServiceIsRunning() const {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS ss{};
    bool running = false;
    if (QueryServiceStatus(svc, &ss))
        running = (ss.dwCurrentState == SERVICE_RUNNING);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return running;
}

bool DriverLoader::WaitForServiceState(uint32_t desiredState, uint32_t timeoutMs) const {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS ss{};
    uint32_t elapsed = 0;
    bool reached = false;

    while (elapsed < timeoutMs) {
        if (!QueryServiceStatus(svc, &ss)) break;
        if (ss.dwCurrentState == desiredState) { reached = true; break; }
        Sleep(250);
        elapsed += 250;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return reached;
}

bool DriverLoader::SvcInstall(const std::string& sysPath) {
    char fullPath[MAX_PATH]{};
    GetFullPathNameA(sysPath.c_str(), MAX_PATH, fullPath, nullptr);

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        Console::Critical("Failed to open SCM — run as Administrator");
        return false;
    }

    if (ServiceExists()) {
        if (ServiceIsRunning()) {
            Console::Info("Driver service already running — reusing");
            CloseServiceHandle(scm);
            ownedService_ = false;
            return true;
        }

        SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_ALL_ACCESS);
        if (svc) {
            SERVICE_STATUS ss{};
            QueryServiceStatus(svc, &ss);

            if (ss.dwCurrentState == SERVICE_STOPPED) {
                Console::Info("Driver service exists but stopped — updating path and starting");
                ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE, fullPath, nullptr, nullptr,
                    nullptr, nullptr, nullptr, nullptr);
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                ownedService_ = true;
                return true;
            }

            if (ss.dwCurrentState == SERVICE_STOP_PENDING) {
                Console::Info("Driver service in STOP_PENDING — waiting...");
                CloseServiceHandle(svc);
                WaitForServiceState(SERVICE_STOPPED, 10000);
                CloseServiceHandle(scm);
                ownedService_ = true;
                return true;
            }

            if (ss.dwCurrentState == SERVICE_START_PENDING) {
                Console::Info("Driver service in START_PENDING — waiting...");
                CloseServiceHandle(svc);
                WaitForServiceState(SERVICE_RUNNING, 10000);
                CloseServiceHandle(scm);
                ownedService_ = false;
                return true;
            }

            Console::Warn("Driver service in unexpected state — deleting and recreating");
            ControlService(svc, SERVICE_CONTROL_STOP, &ss);
            WaitForServiceState(SERVICE_STOPPED, 5000);
            ::DeleteService(svc);
            CloseServiceHandle(svc);
        }
    }

    SC_HANDLE svc = CreateServiceA(
        scm,
        kServiceName,
        kDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        fullPath,
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            Console::Info("Service already exists (race) — proceeding");
            CloseServiceHandle(scm);
            ownedService_ = true;
            return true;
        }
        Console::Critical(("Failed to create driver service — error " +
            std::to_string(err)).c_str());
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    ownedService_ = true;
    return true;
}

bool DriverLoader::SvcStart() {
    if (ServiceIsRunning()) return true;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = ::StartServiceA(svc, 0, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return true;
        }
        Console::Critical(("Failed to start driver — error " +
            std::to_string(err)).c_str());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return WaitForServiceState(SERVICE_RUNNING, 10000);
}

bool DriverLoader::SvcStop() {
    if (!ServiceIsRunning()) return true;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return WaitForServiceState(SERVICE_STOPPED, 10000);
}

bool DriverLoader::SvcRemove() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, kServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        return (err == ERROR_SERVICE_DOES_NOT_EXIST);
    }

    SERVICE_STATUS ss{};
    if (ServiceIsRunning()) {
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        WaitForServiceState(SERVICE_STOPPED, 10000);
    }

    BOOL ok = ::DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
}

bool DriverLoader::OpenDevice() {
    for (int attempt = 0; attempt < 10; ++attempt) {
        device_ = CreateFileW(
            kDevicePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (device_ != INVALID_HANDLE_VALUE) return true;

        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            Sleep(500);
            continue;
        }
        break;
    }

    Console::Critical(("Failed to open driver device — error " +
        std::to_string(GetLastError())).c_str());
    return false;
}

void DriverLoader::CloseDevice() {
    if (device_ != INVALID_HANDLE_VALUE) {
        CloseHandle(device_);
        device_ = INVALID_HANDLE_VALUE;
    }
}

bool DriverLoader::Load() {
    if (loaded_) return true;

    if (!IsAdmin()) {
        Console::Warn("Not running as Administrator — driver loading skipped");
        Console::Info("Run as Administrator to enable kernel-level monitoring");
        return false;
    }

    if (!IsTestSigningEnabled()) {
        Console::Warn("Test signing not enabled — unsigned driver may fail to load");
        Console::Info("Enable with: bcdedit /set testsigning on (reboot required)");
    }

    std::string sysPath = FindDriverPath();
    if (sysPath.empty()) {
        Console::Warn("monitor-driver.sys not found — kernel monitoring disabled");
        return false;
    }
    Console::Info(("Found driver: " + sysPath).c_str());

    if (!SvcInstall(sysPath)) return false;
    Console::Ok("Driver service installed");

    if (!SvcStart()) {
        Console::Critical("Failed to start driver service");
        if (ownedService_) SvcRemove();
        return false;
    }
    Console::Ok("Driver service started");

    if (!OpenDevice()) {
        Console::Critical("Failed to open driver device");
        if (ownedService_) { SvcStop(); SvcRemove(); }
        return false;
    }
    Console::Ok("Driver device opened");

    loaded_ = true;
    return true;
}

void DriverLoader::Unload() {
    StopPolling();
    CloseDevice();

    if (loaded_ && ownedService_) {
        Console::Info("Stopping driver service...");
        SvcStop();
        Console::Info("Removing driver service...");
        SvcRemove();
    }

    loaded_ = false;
}

void DriverLoader::StartPolling() {
    if (!loaded_ || polling_.exchange(true)) return;

    pollThread_ = std::thread(&DriverLoader::PollLoop, this);
    Console::Ok("Driver event polling started");
}

void DriverLoader::StopPolling() {
    polling_ = false;
    if (pollThread_.joinable())
        pollThread_.join();
}

void DriverLoader::PollLoop() {
    constexpr size_t kBatchSize = 64;
    constexpr size_t kBufSize   = kBatchSize * sizeof(KernelEvent);

    auto buf = std::make_unique<uint8_t[]>(kBufSize);

    while (polling_) {
        if (device_ == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            if (!OpenDevice()) continue;
        }

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            device_,
            IOCTL_GET_EVENTS,
            nullptr, 0,
            buf.get(), static_cast<DWORD>(kBufSize),
            &bytesReturned,
            nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_DEVICE_NOT_CONNECTED ||
                err == ERROR_DEV_NOT_EXIST) {
                Console::Warn("Driver device disconnected — attempting reconnect...");
                CloseDevice();
                Sleep(2000);
                continue;
            }
            Sleep(50);
            continue;
        }

        size_t eventCount = bytesReturned / sizeof(KernelEvent);
        auto events = reinterpret_cast<const KernelEvent*>(buf.get());

        for (size_t i = 0; i < eventCount; ++i) {
            ProcessKernelEvent(events[i]);
        }

        if (eventCount == 0) {
            Sleep(50);
        }
    }
}

void DriverLoader::ProcessKernelEvent(const KernelEvent& kev) {
    static const uint32_t kOwnPid = static_cast<uint32_t>(GetCurrentProcessId());

    if (kev.callerPid == kOwnPid) return;
    if (kev.targetPid == kOwnPid) return;

    HookGuard::Scope suppress;

    auto& cache = ProcessCache::Instance();
    auto callerName = cache.GetName(kev.callerPid);
    auto targetName = cache.GetName(kev.targetPid);

    ApiType api = ApiType::OpenProcess;
    Severity sev = Severity::Info;

    switch (static_cast<KernelEventKind>(kev.kind)) {
        case ProcessOpen:
            api = ApiType::OpenProcess;
            sev = ClassifySeverity(ApiType::OpenProcess, kev.grantedAccess);

            if (Trusted::ShouldSuppressProcessEvent(
                    callerName.c_str(), targetName.c_str(),
                    kev.grantedAccess, false))
                return;
            break;

        case ProcessCreate:
            api = ApiType::NtCreateThreadEx;
            sev = Severity::Info;
            break;

        case ProcessTerminate:
            api = ApiType::NtCreateThreadEx;
            sev = Severity::Info;
            break;

        default:
            return;
    }

    ProcessEvent ev{};
    ev.id          = g_drvId.fetch_add(1);
    ev.timestampMs = kev.timestampMs;
    ev.api         = api;
    ev.severity    = sev;
    ev.origin      = CallOrigin::Direct;
    ev.callerPid   = kev.callerPid;
    ev.targetPid   = kev.targetPid;
    ev.param1      = kev.grantedAccess;
    ev.param2      = 0;
    ev.param3      = 0;
    ev.returnValue = 0;
    ev.success     = true;

    strncpy_s(ev.callerName, callerName.c_str(), _TRUNCATE);
    strncpy_s(ev.targetName, targetName.c_str(), _TRUNCATE);

    if (kev.imagePath[0] && targetName.empty()) {
        char narrow[260]{};
        WideCharToMultiByte(CP_UTF8, 0, kev.imagePath, -1,
                            narrow, sizeof(narrow), nullptr, nullptr);
        strncpy_s(ev.targetName, narrow, _TRUNCATE);
    }

    PipeClient::Instance().Send(ev);
}
