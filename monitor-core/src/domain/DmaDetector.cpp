#include "pch.hpp"
#include "DmaDetector.hpp"
#include "PciScanner.hpp"
#include "SignatureVerifier.hpp"
#include "TrustedProcesses.hpp"
#include "../core/EventTypes.hpp"
#include "../core/HookGuard.hpp"
#include "../ipc/PipeClient.hpp"
#include "../system/ProcessCache.hpp"
#include "../console/Console.hpp"

#include <TlHelp32.h>
#include <winreg.h>

static std::atomic<uint64_t> g_hwId{ 100000 };

static void EmitHw(HwEventType type, Severity sev, ThreatLevel threat,
                   const char* device, const char* detail,
                   uint16_t vid = 0, uint16_t did = 0,
                   uint16_t subVid = 0, uint16_t subDid = 0,
                   const char* location = "", bool flagged = false)
{
    HardwareEvent ev{};
    ev.id          = g_hwId.fetch_add(1);
    ev.timestampMs = NowMs();
    ev.type        = type;
    ev.severity    = sev;
    ev.threat      = threat;
    ev.vendorId    = vid;
    ev.deviceId    = did;
    ev.subVendorId = subVid;
    ev.subDeviceId = subDid;
    ev.flagged     = flagged;
    strncpy_s(ev.deviceName, device, _TRUNCATE);
    strncpy_s(ev.detail, detail, _TRUNCATE);
    strncpy_s(ev.location, location, _TRUNCATE);
    PipeClient::Instance().SendHardware(ev);
}

DmaDetector& DmaDetector::Instance() {
    static DmaDetector inst;
    return inst;
}

void DmaDetector::RunFullScan() {
    HookGuard::Scope suppress;
    CheckIommu();
    CheckAcpiDmar();
    ScanPciDevices();
    VerifyRunningProcessSignatures();
}

void DmaDetector::StartPeriodicScan(uint32_t intervalMs) {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&DmaDetector::ScanLoop, this, intervalMs);
    thread_.detach();
}

void DmaDetector::Stop() {
    running_ = false;
}

void DmaDetector::ScanLoop(uint32_t intervalMs) {
    while (running_) {
        {
            HookGuard::Scope suppress;
            ScanPciDevices();
        }

        uint32_t elapsed = 0;
        while (running_ && elapsed < intervalMs) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            elapsed += 500;
        }
    }
}

void DmaDetector::ScanPciDevices() {
    auto devices = PciScanner::Instance().Scan();
    uint32_t totalPci   = 0;
    uint32_t flaggedCnt = 0;

    for (const auto& dev : devices) {
        totalPci++;

        if (dev.isKnownDma) {
            flaggedCnt++;
            std::string detail = dev.threatReason + " | HW: " + dev.hardwareId;
            EmitHw(HwEventType::DmaDeviceFound, Severity::Critical, ThreatLevel::Dangerous,
                   dev.description.c_str(), detail.c_str(),
                   dev.vendorId, dev.deviceId, dev.subVendorId, dev.subDeviceId,
                   dev.location.c_str(), true);

            Console::Critical(("DMA DEVICE: " + dev.description +
                " [VID:" + std::to_string(dev.vendorId) +
                " DID:" + std::to_string(dev.deviceId) + "] " +
                dev.threatReason).c_str());
        }
        else if (dev.isFpga) {
            flaggedCnt++;
            std::string detail = dev.threatReason + " | HW: " + dev.hardwareId;
            EmitHw(HwEventType::DmaDeviceFound, Severity::Warning, ThreatLevel::Suspicious,
                   dev.description.c_str(), detail.c_str(),
                   dev.vendorId, dev.deviceId, dev.subVendorId, dev.subDeviceId,
                   dev.location.c_str(), true);

            Console::Warn(("FPGA VENDOR: " + dev.description +
                " [VID:0x" + std::to_string(dev.vendorId) + "]").c_str());
        }
    }

    std::string summary = std::to_string(totalPci) + " PCI devices scanned, " +
                          std::to_string(flaggedCnt) + " flagged";

    Severity scanSev = flaggedCnt > 0 ? Severity::Warning : Severity::Info;
    EmitHw(HwEventType::PciDeviceScan, scanSev, ThreatLevel::Safe,
           "PCI Bus", summary.c_str());

    if (flaggedCnt == 0) {
        Console::Ok(("PCI scan clean: " + std::to_string(totalPci) + " devices, 0 flagged").c_str());
    }
}

void DmaDetector::CheckIommu() {
    bool iommuEnabled = false;
    std::string tech  = "Unknown";

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val);
        if (RegQueryValueExA(hKey, "Enabled", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS) {
            if (val) iommuEnabled = true;
        }
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DmaSecurity",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val);
        if (RegQueryValueExA(hKey, "BootDMAProtection", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS) {
            if (val) { iommuEnabled = true; tech = "Kernel DMA Protection"; }
        }
        RegCloseKey(hKey);
    }

    if (!iommuEnabled) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\intelppm",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            tech = "Intel VT-d (service present)";
            RegCloseKey(hKey);
        }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\amdppm",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            tech = "AMD-Vi (service present)";
            RegCloseKey(hKey);
        }
    }

    if (iommuEnabled) {
        EmitHw(HwEventType::IommuStatus, Severity::Info, ThreatLevel::Safe,
               tech.c_str(), "IOMMU/DMA protection is enabled");
        Console::Ok(("IOMMU: " + tech + " — enabled").c_str());
    } else {
        EmitHw(HwEventType::IommuStatus, Severity::Critical, ThreatLevel::Dangerous,
               tech.c_str(),
               "IOMMU/DMA protection is DISABLED — system is vulnerable to DMA attacks",
               0, 0, 0, 0, "", true);
        Console::Critical("IOMMU: DMA protection is DISABLED — vulnerable to DMA attacks!");
    }
}

void DmaDetector::CheckAcpiDmar() {
    UINT tableSize = GetSystemFirmwareTable('ACPI', 'RAMD', nullptr, 0);

    if (tableSize > 0) {
        std::vector<uint8_t> buf(tableSize);
        if (GetSystemFirmwareTable('ACPI', 'RAMD', buf.data(), tableSize) > 0) {
            EmitHw(HwEventType::IommuStatus, Severity::Info, ThreatLevel::Safe,
                   "ACPI DMAR", "Intel VT-d DMAR table present in firmware");
            Console::Ok("ACPI: Intel VT-d DMAR table found");
            return;
        }
    }

    tableSize = GetSystemFirmwareTable('ACPI', 'RAVI', nullptr, 0);
    if (tableSize > 0) {
        EmitHw(HwEventType::IommuStatus, Severity::Info, ThreatLevel::Safe,
               "ACPI IVRS", "AMD-Vi IVRS table present in firmware");
        Console::Ok("ACPI: AMD-Vi IVRS table found");
        return;
    }

    EmitHw(HwEventType::IommuStatus, Severity::Warning, ThreatLevel::Suspicious,
           "ACPI", "No DMAR/IVRS table found — IOMMU may not be available");
    Console::Warn("ACPI: No DMAR/IVRS table — IOMMU hardware may be absent");
}

void DmaDetector::VerifyRunningProcessSignatures() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    uint32_t checked      = 0;
    uint32_t unsigned_cnt = 0;
    uint32_t skipped      = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            char exeName[260]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                exeName, sizeof(exeName), nullptr, nullptr);

            if (Trusted::IsTrustedCaller(exeName)) {
                skipped++;
                continue;
            }

            auto sig = SignatureVerifier::VerifyPid(pe.th32ProcessID);
            checked++;

            if (sig.status == SignatureStatus::Valid) continue;
            if (!sig.signer.empty() && Trusted::IsTrustedSigner(sig.signer)) continue;
            if (sig.status == SignatureStatus::Error) continue;

            if (sig.status == SignatureStatus::Unsigned ||
                sig.status == SignatureStatus::Invalid  ||
                sig.status == SignatureStatus::Untrusted) {

                unsigned_cnt++;

                Severity sev = (sig.status == SignatureStatus::Invalid)
                    ? Severity::Critical : Severity::Warning;

                std::string detail = "Status: ";
                detail += SignatureStatusName(sig.status);
                if (!sig.signer.empty()) detail += " | Signer: " + sig.signer;

                EmitHw(HwEventType::SignatureCheck, sev,
                       sig.status == SignatureStatus::Invalid
                           ? ThreatLevel::Dangerous : ThreatLevel::Suspicious,
                       exeName, detail.c_str(),
                       0, 0, 0, 0, "", true);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    std::string summary = std::to_string(checked) + " processes checked, " +
                          std::to_string(unsigned_cnt) + " flagged, " +
                          std::to_string(skipped) + " trusted (skipped)";
    EmitHw(HwEventType::SignatureCheck, Severity::Info, ThreatLevel::Safe,
           "Signature Scan", summary.c_str());

    Console::Info(("Signatures: " + summary).c_str());
}
