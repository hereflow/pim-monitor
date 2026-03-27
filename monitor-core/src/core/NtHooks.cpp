#include "pch.hpp"
#include "NtHooks.hpp"
#include "HookGuard.hpp"
#include "EventTypes.hpp"
#include "../domain/NtTypes.hpp"
#include "../domain/SyscallMap.hpp"
#include "../domain/TrustedProcesses.hpp"
#include "../system/ProcessCache.hpp"
#include "../ipc/PipeClient.hpp"

static std::atomic<uint64_t> g_id{ 10000 };
static const uint32_t       kOwnPid = static_cast<uint32_t>(GetCurrentProcessId());

static void EmitNt(ApiType api, uint32_t targetPid, uint64_t p1, uint64_t p2,
                   uint64_t ret, bool ok, void* returnAddr)
{
    uint32_t callerPid = kOwnPid;
    if (callerPid == targetPid) return;

    auto& cache = ProcessCache::Instance();
    auto& smap  = SyscallMap::Instance();

    bool suspicious = smap.IsCallerSuspicious(returnAddr);

    auto caller = cache.GetName(callerPid);
    auto target = cache.GetName(targetPid);

    if ((api == ApiType::NtOpenProcess) &&
        Trusted::ShouldSuppressProcessEvent(caller.c_str(), target.c_str(), p1, suspicious))
        return;

    ProcessEvent ev{};
    ev.id               = g_id.fetch_add(1);
    ev.timestampMs      = NowMs();
    ev.api              = api;
    ev.severity         = ClassifySeverity(api, p1);
    ev.origin           = smap.IsWithinNtdll(returnAddr) ? CallOrigin::NtLayer : CallOrigin::Api;
    ev.suspiciousCaller = suspicious;
    ev.callerPid        = callerPid;
    ev.targetPid        = targetPid;
    ev.param1           = p1;
    ev.param2           = p2;
    ev.returnValue      = ret;
    ev.success          = ok;

    if (ev.suspiciousCaller && ev.severity < Severity::Critical)
        ev.severity = Severity::Critical;

    strncpy_s(ev.callerName, caller.c_str(), _TRUNCATE);
    strncpy_s(ev.targetName, target.c_str(), _TRUNCATE);

    PipeClient::Instance().Send(ev);
}

static Nt::FnNtOpenProcess           g_NtOpenProcess{};
static Nt::FnNtReadVirtualMemory     g_NtReadVirtualMemory{};
static Nt::FnNtWriteVirtualMemory    g_NtWriteVirtualMemory{};
static Nt::FnNtAllocateVirtualMemory g_NtAllocateVirtualMemory{};
static Nt::FnNtCreateThreadEx        g_NtCreateThreadEx{};

static Nt::NTSTATUS NTAPI H_NtOpenProcess(
    PHANDLE handle, ACCESS_MASK access,
    Nt::ObjectAttributes* attr, Nt::ClientId* cid)
{
    Nt::NTSTATUS r = g_NtOpenProcess(handle, access, attr, cid);
    uint32_t pid = cid ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cid->UniqueProcess)) : 0;
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    void* ra = _ReturnAddress();
    EmitNt(ApiType::NtOpenProcess, pid, access, 0, (uint64_t)r, r >= 0, ra);
    HookGuard::Active = false;
    return r;
}

static Nt::NTSTATUS NTAPI H_NtReadVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T sz, PSIZE_T read)
{
    Nt::NTSTATUS r = g_NtReadVirtualMemory(proc, base, buf, sz, read);
    uint32_t pid = GetProcessId(proc);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    void* ra = _ReturnAddress();
    EmitNt(ApiType::NtReadVirtualMemory, pid, reinterpret_cast<uint64_t>(base), sz, (uint64_t)r, r >= 0, ra);
    HookGuard::Active = false;
    return r;
}

static Nt::NTSTATUS NTAPI H_NtWriteVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T sz, PSIZE_T written)
{
    Nt::NTSTATUS r = g_NtWriteVirtualMemory(proc, base, buf, sz, written);
    uint32_t pid = GetProcessId(proc);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    void* ra = _ReturnAddress();
    EmitNt(ApiType::NtWriteVirtualMemory, pid, reinterpret_cast<uint64_t>(base), sz, (uint64_t)r, r >= 0, ra);
    HookGuard::Active = false;
    return r;
}

static Nt::NTSTATUS NTAPI H_NtAllocateVirtualMemory(
    HANDLE proc, PVOID* base, ULONG_PTR zero, PSIZE_T sz, ULONG type, ULONG prot)
{
    Nt::NTSTATUS r = g_NtAllocateVirtualMemory(proc, base, zero, sz, type, prot);
    if (proc == GetCurrentProcess()) return r;
    uint32_t pid = GetProcessId(proc);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    void* ra = _ReturnAddress();
    SIZE_T allocated = sz ? *sz : 0;
    EmitNt(ApiType::NtAllocateVirtual, pid, allocated, type, (uint64_t)r, r >= 0, ra);
    HookGuard::Active = false;
    return r;
}

static Nt::NTSTATUS NTAPI H_NtCreateThreadEx(
    PHANDLE thread, ACCESS_MASK access, Nt::ObjectAttributes* attr,
    HANDLE proc, PVOID start, PVOID arg, ULONG flags,
    SIZE_T zero, SIZE_T stack, SIZE_T maxStack, PVOID list)
{
    Nt::NTSTATUS r = g_NtCreateThreadEx(thread, access, attr, proc, start, arg,
                                         flags, zero, stack, maxStack, list);
    uint32_t pid = GetProcessId(proc);
    if (pid == 0 || pid == kOwnPid) return r;
    if (HookGuard::Active) return r;
    HookGuard::Active = true;
    void* ra = _ReturnAddress();
    EmitNt(ApiType::NtCreateThreadEx, pid, reinterpret_cast<uint64_t>(start), 0, (uint64_t)r, r >= 0, ra);
    HookGuard::Active = false;
    return r;
}

#define MH_TRY(expr) do { if ((expr) != MH_OK) return false; } while(0)

bool NtHooks::Install() {
    SyscallMap::Instance().Build();

    MH_TRY(MH_CreateHookApi(L"ntdll", "NtOpenProcess",
        (LPVOID)H_NtOpenProcess, (LPVOID*)&g_NtOpenProcess));
    MH_TRY(MH_CreateHookApi(L"ntdll", "NtReadVirtualMemory",
        (LPVOID)H_NtReadVirtualMemory, (LPVOID*)&g_NtReadVirtualMemory));
    MH_TRY(MH_CreateHookApi(L"ntdll", "NtWriteVirtualMemory",
        (LPVOID)H_NtWriteVirtualMemory, (LPVOID*)&g_NtWriteVirtualMemory));
    MH_TRY(MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory",
        (LPVOID)H_NtAllocateVirtualMemory, (LPVOID*)&g_NtAllocateVirtualMemory));
    MH_TRY(MH_CreateHookApi(L"ntdll", "NtCreateThreadEx",
        (LPVOID)H_NtCreateThreadEx, (LPVOID*)&g_NtCreateThreadEx));

    MH_TRY(MH_EnableHook(MH_ALL_HOOKS));
    return true;
}

void NtHooks::Remove() {
    MH_DisableHook((LPVOID)g_NtOpenProcess);
    MH_DisableHook((LPVOID)g_NtReadVirtualMemory);
    MH_DisableHook((LPVOID)g_NtWriteVirtualMemory);
    MH_DisableHook((LPVOID)g_NtAllocateVirtualMemory);
    MH_DisableHook((LPVOID)g_NtCreateThreadEx);
}
