#pragma once
#include <string>
#include <unordered_map>
#include <cstdint>

class SyscallMap {
public:
    static SyscallMap& Instance();

    void Build();

    uint32_t    SsnOf(const char* ntFuncName) const;
    const char* NameOf(uint32_t ssn) const;

    bool IsCallerSuspicious(void* returnAddr) const;
    bool IsWithinNtdll(void* addr) const;

private:
    SyscallMap() = default;

    void ScanExports();

    static uint32_t ExtractSsn(const uint8_t* stub);

    std::unordered_map<std::string, uint32_t> nameToSsn_;
    std::unordered_map<uint32_t, std::string> ssnToName_;

    uintptr_t ntdllBase_{ 0 };
    uintptr_t ntdllEnd_ { 0 };
};
