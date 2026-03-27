#include "pch.hpp"
#include "Hooks.hpp"
#include "HookGuard.hpp"
#include "EventTypes.hpp"
#include "../domain/TrustedProcesses.hpp"
#include "../system/ProcessCache.hpp"
#include "../ipc/PipeClient.hpp"

static std::atomic<uint64_t> g_id{ 1 };
static const uint32_t       kOwnPid = static_cast<uint32_t>(GetCurrentProcessId());

static void Emit(ApiType api, uint32_t targetPid,
                 uint64_t p1, uint64_t p2, uint64_t p3,
                 uint64_t ret, bool ok)
{
    uint32_t callerPid = kOwnPid;
    if (callerPid == targetPid) return;

    auto& cache = ProcessCache::Instance();
    auto caller = cache.GetName(callerPid);
    auto target = cache.GetName(targetPid);

    if ((api == ApiType::OpenProcess || api == ApiType::NtOpenProcess) &&
        Trusted::ShouldSuppressProcessEvent(caller.c_str(), target.c_str(), p1, false))
        return;

    ProcessEvent ev{};
    ev.id          = g_id.fetch_add(1);
    ev.timestampMs = NowMs();
    ev.api         = api;
    ev.severity    = ClassifySeverity(api, p1);
    ev.origin      = CallOrigin::Api;
    ev.callerPid   = callerPid;
    ev.targetPid   = targetPid;
    ev.param1      = p1;
    ev.param2      = p2;
    ev.param3      = p3;
    ev.returnValue = ret;
    ev.success     = ok;

    strncpy_s(ev.callerName, caller.c_str(), _TRUNCATE);
    strncpy_s(ev.targetName, target.c_str(), _TRUNCATE);

    PipeClient::Instance().Send(ev);
}

using FnOpenProcess        = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using FnReadProcessMemory  = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
using FnWriteProcessMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using FnVirtualAllocEx     = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using FnCreateRemoteThread = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                              LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

static FnOpenProcess        g_OpenProcess{};
static FnReadProcessMemory  g_ReadProcessMemory{};
static FnWriteProcessMemory g_WriteProcessMemory{};
static FnVirtualAllocEx     g_VirtualAllocEx{};
static FnCreateRemoteThread g_CreateRemoteThread{};

static HANDLE WINAPI H_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    HANDLE r = g_OpenProcess(access, inherit, pid);
    if (static_cast<uint32_t>(pid) == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    Emit(ApiType::OpenProcess, pid, access, 0, 0, (uint64_t)r, r != nullptr);
    HookGuard::Active = false;
    return r;
}

static BOOL WINAPI H_ReadProcessMemory(HANDLE h, LPCVOID base, LPVOID buf, SIZE_T sz, SIZE_T* read) {
    BOOL r = g_ReadProcessMemory(h, base, buf, sz, read);
    uint32_t pid = GetProcessId(h);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    Emit(ApiType::ReadProcessMemory, pid, (uint64_t)base, sz, 0, r, r != FALSE);
    HookGuard::Active = false;
    return r;
}

static BOOL WINAPI H_WriteProcessMemory(HANDLE h, LPVOID base, LPCVOID buf, SIZE_T sz, SIZE_T* written) {
    BOOL r = g_WriteProcessMemory(h, base, buf, sz, written);
    uint32_t pid = GetProcessId(h);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    Emit(ApiType::WriteProcessMemory, pid, (uint64_t)base, sz, 0, r, r != FALSE);
    HookGuard::Active = false;
    return r;
}

static LPVOID WINAPI H_VirtualAllocEx(HANDLE h, LPVOID addr, SIZE_T sz, DWORD type, DWORD prot) {
    LPVOID r = g_VirtualAllocEx(h, addr, sz, type, prot);
    uint32_t pid = GetProcessId(h);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    Emit(ApiType::VirtualAllocEx, pid, sz, type, prot, (uint64_t)r, r != nullptr);
    HookGuard::Active = false;
    return r;
}

static HANDLE WINAPI H_CreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES attr, SIZE_T stack,
                                           LPTHREAD_START_ROUTINE start, LPVOID param,
                                           DWORD flags, LPDWORD tid) {
    HANDLE r = g_CreateRemoteThread(h, attr, stack, start, param, flags, tid);
    uint32_t pid = GetProcessId(h);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    Emit(ApiType::CreateRemoteThread, pid, (uint64_t)start, 0, 0, (uint64_t)r, r != nullptr);
    HookGuard::Active = false;
    return r;
}

#define MH_TRY(expr) do { if ((expr) != MH_OK) return false; } while(0)

bool Hooks::Install() {
    MH_TRY(MH_Initialize());
    MH_TRY(MH_CreateHookApi(L"kernel32", "OpenProcess",        (LPVOID)H_OpenProcess,        (LPVOID*)&g_OpenProcess));
    MH_TRY(MH_CreateHookApi(L"kernel32", "ReadProcessMemory",  (LPVOID)H_ReadProcessMemory,  (LPVOID*)&g_ReadProcessMemory));
    MH_TRY(MH_CreateHookApi(L"kernel32", "WriteProcessMemory", (LPVOID)H_WriteProcessMemory, (LPVOID*)&g_WriteProcessMemory));
    MH_TRY(MH_CreateHookApi(L"kernel32", "VirtualAllocEx",     (LPVOID)H_VirtualAllocEx,     (LPVOID*)&g_VirtualAllocEx));
    MH_TRY(MH_CreateHookApi(L"kernel32", "CreateRemoteThread", (LPVOID)H_CreateRemoteThread, (LPVOID*)&g_CreateRemoteThread));
    MH_TRY(MH_EnableHook(MH_ALL_HOOKS));
    return true;
}

void Hooks::Remove() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}
