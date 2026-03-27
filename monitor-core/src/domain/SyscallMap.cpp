#include "pch.hpp"
#include "SyscallMap.hpp"

SyscallMap& SyscallMap::Instance() {
    static SyscallMap inst;
    return inst;
}

void SyscallMap::Build() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    MODULEINFO mi{};
    if (GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi))) {
        ntdllBase_ = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        ntdllEnd_  = ntdllBase_ + mi.SizeOfImage;
    }

    ScanExports();
}

uint32_t SyscallMap::SsnOf(const char* name) const {
    auto it = nameToSsn_.find(name);
    return (it != nameToSsn_.end()) ? it->second : 0xFFFFFFFF;
}

const char* SyscallMap::NameOf(uint32_t ssn) const {
    auto it = ssnToName_.find(ssn);
    return (it != ssnToName_.end()) ? it->second.c_str() : nullptr;
}

bool SyscallMap::IsWithinNtdll(void* addr) const {
    auto a = reinterpret_cast<uintptr_t>(addr);
    return (a >= ntdllBase_ && a < ntdllEnd_);
}

bool SyscallMap::IsCallerSuspicious(void* returnAddr) const {
    if (!returnAddr) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(returnAddr, &mbi, sizeof(mbi))) return true;

    if (mbi.Type != MEM_IMAGE)           return true;
    if (mbi.State != MEM_COMMIT)         return true;
    if (mbi.Protect & PAGE_NOACCESS)     return true;
    if (mbi.AllocationBase == nullptr)   return true;

    char path[MAX_PATH]{};
    if (!GetMappedFileNameA(GetCurrentProcess(), returnAddr, path, MAX_PATH))
        return true;

    return false;
}

void SyscallMap::ScanExports() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    auto base  = reinterpret_cast<uint8_t*>(ntdll);
    auto dos   = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto pe    = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& dir  = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto  exp  = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);

    auto names  = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    auto rvas   = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    auto ords   = reinterpret_cast<WORD*> (base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (name[0] != 'Z' || name[1] != 'w') continue;

        auto stub = base + rvas[ords[i]];
        uint32_t ssn = ExtractSsn(stub);
        if (ssn == 0xFFFFFFFF) continue;

        std::string ntName = "Nt";
        ntName += (name + 2);

        nameToSsn_[ntName] = ssn;
        ssnToName_[ssn]    = ntName;
    }
}

uint32_t SyscallMap::ExtractSsn(const uint8_t* stub) {
    for (int offset = 0; offset < 32; ++offset) {
        if (stub[offset]     == 0xB8 &&
            stub[offset + 4] == 0x00 &&
            stub[offset + 5] == 0x00 &&
            stub[offset + 6] == 0x00) {
            return *reinterpret_cast<const uint32_t*>(stub + offset + 1);
        }
    }
    return 0xFFFFFFFF;
}
