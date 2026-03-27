#pragma once
#include <cstdint>
#include <thread>
#include <atomic>

class DmaDetector {
public:
    static DmaDetector& Instance();

    void RunFullScan();
    void StartPeriodicScan(uint32_t intervalMs = 30000);
    void Stop();

private:
    DmaDetector() = default;

    void ScanPciDevices();
    void CheckIommu();
    void CheckAcpiDmar();
    void VerifyRunningProcessSignatures();
    void ScanLoop(uint32_t intervalMs);

    std::thread       thread_;
    std::atomic<bool> running_{ false };
};
