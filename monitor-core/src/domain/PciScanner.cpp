#include "pch.hpp"
#include "PciScanner.hpp"

#include <SetupAPI.h>
#include <devguid.h>
#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

const PciScanner::KnownDmaEntry PciScanner::kDmaDevices[] = {
    { 0x10EE, 0x0666, "PCILeech default firmware (Screamer/Squirrel/AC701)" },
    { 0x10EE, 0x0007, "Xilinx default PCIe endpoint (DMA board)" },
    { 0x10EE, 0x0300, "Xilinx Spartan-3 PCIe design" },
    { 0x10EE, 0x0600, "Xilinx Spartan-6 PCIe design" },
    { 0x10EE, 0x7011, "Xilinx Artix-7 35T (PCIe hard block)" },
    { 0x10EE, 0x7021, "Xilinx Artix-7 100T" },
    { 0x10EE, 0x7022, "Xilinx Artix-7 200T" },
    { 0x10EE, 0x7024, "Xilinx Kintex-7 325T" },
    { 0x10EE, 0x7028, "Xilinx Kintex-7 480T" },
    { 0x10EE, 0x7031, "Xilinx Kintex UltraScale" },
    { 0x10EE, 0x7038, "Xilinx FPGA Card XC7VX690T" },
    { 0x10EE, 0x5000, "Xilinx Alveo U200 XDMA" },
    { 0x10EE, 0x5004, "Xilinx Alveo U250 XDMA" },
    { 0x10EE, 0x5020, "Xilinx Alveo U50 XDMA" },
    { 0x10EE, 0x5001, "Xilinx Versal Prime" },
    { 0x10EE, 0x9011, "Xilinx Alveo U200" },
    { 0x10EE, 0x9031, "Xilinx Alveo U250" },
    { 0x10EE, 0x903F, "Xilinx Alveo U280" },
    { 0x10EE, 0x9134, "Xilinx SmartSSD variant" },
    { 0x10EE, 0x9234, "Xilinx SmartSSD variant" },
    { 0x10EE, 0x9434, "Xilinx SmartSSD variant" },
    { 0x10EE, 0x6987, "Xilinx SmartSSD variant" },
    { 0x10EE, 0x6988, "Xilinx SmartSSD variant" },
    { 0x10EE, 0xB034, "Xilinx Artix UltraScale+" },
    { 0x1172, 0x0004, "Altera PF5102 board" },
    { 0x1172, 0x0005, "Altera Arria V" },
    { 0x1172, 0x00A7, "Altera Stratix V" },
    { 0x1172, 0x0530, "Altera Stratix IV" },
    { 0x1172, 0x646C, "Altera KT-500/KT-521 board" },
    { 0x1172, 0xE001, "Altera Stratix V (alt)" },
    { 0x1204, 0x5303, "Lattice ECP5" },
    { 0x1204, 0x9C1D, "Lattice CrossLink-NX PCIe Bridge" },
    { 0x1234, 0x1111, "LambdaConcept PCIe Screamer" },
    { 0x1D0F, 0xF001, "AWS FPGA (potential spoof)" },
};

const uint16_t PciScanner::kFpgaVendors[] = {
    0x10EE,
    0x1172,
    0x1204,
    0x1234,
    0x10B5,
    0x12D8,
    0x1D0F,
};

PciScanner& PciScanner::Instance() {
    static PciScanner inst;
    return inst;
}

bool PciScanner::IsFpgaVendor(uint16_t vid) const {
    for (auto v : kFpgaVendors)
        if (v == vid) return true;
    return false;
}

bool PciScanner::IsKnownDma(uint16_t vid, uint16_t did, std::string& outReason) const {
    for (const auto& entry : kDmaDevices) {
        if (entry.vendorId == vid && entry.deviceId == did) {
            outReason = entry.name;
            return true;
        }
    }
    return false;
}

bool PciScanner::ParseHardwareIds(const std::string& hwid,
                                   uint16_t& vid, uint16_t& did,
                                   uint16_t& subVid, uint16_t& subDid) const {
    vid = did = subVid = subDid = 0;

    auto parseHex = [](const std::string& s, const std::string& prefix) -> uint16_t {
        auto pos = s.find(prefix);
        if (pos == std::string::npos) return 0;
        return static_cast<uint16_t>(std::strtoul(s.c_str() + pos + prefix.size(), nullptr, 16));
    };

    vid    = parseHex(hwid, "VEN_");
    did    = parseHex(hwid, "DEV_");
    subVid = parseHex(hwid, "SUBSYS_");

    auto subsysPos = hwid.find("SUBSYS_");
    if (subsysPos != std::string::npos && hwid.size() >= subsysPos + 15) {
        uint32_t full = static_cast<uint32_t>(std::strtoul(
            hwid.c_str() + subsysPos + 7, nullptr, 16));
        subDid = static_cast<uint16_t>(full >> 16);
        subVid = static_cast<uint16_t>(full & 0xFFFF);
    }

    return vid != 0;
}

std::vector<PciDeviceInfo> PciScanner::Scan() {
    std::vector<PciDeviceInfo> results;

    HDEVINFO devInfo = SetupDiGetClassDevsA(
        nullptr, "PCI", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);

    if (devInfo == INVALID_HANDLE_VALUE) return results;

    SP_DEVINFO_DATA devData{};
    devData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &devData); ++i) {
        PciDeviceInfo dev{};

        char buf[1024]{};
        DWORD sz = 0;

        if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_HARDWAREID,
                nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), &sz)) {
            dev.hardwareId = buf;
        }

        if (dev.hardwareId.empty()) continue;

        ParseHardwareIds(dev.hardwareId, dev.vendorId, dev.deviceId,
                         dev.subVendorId, dev.subDeviceId);

        memset(buf, 0, sizeof(buf));
        if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_DEVICEDESC,
                nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), &sz)) {
            dev.description = buf;
        }

        memset(buf, 0, sizeof(buf));
        if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_LOCATION_INFORMATION,
                nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), &sz)) {
            dev.location = buf;
        }

        char instanceBuf[512]{};
        if (SetupDiGetDeviceInstanceIdA(devInfo, &devData, instanceBuf, sizeof(instanceBuf), nullptr)) {
            dev.instanceId = instanceBuf;
        }

        std::string reason;
        dev.isKnownDma = IsKnownDma(dev.vendorId, dev.deviceId, reason);
        dev.isFpga     = IsFpgaVendor(dev.vendorId);
        dev.threatReason = reason;

        if (dev.isFpga && !dev.isKnownDma) {
            dev.threatReason = "FPGA vendor detected on PCI bus";
        }

        results.push_back(std::move(dev));
    }

    SetupDiDestroyDeviceInfoList(devInfo);
    return results;
}

std::vector<PciDeviceInfo> PciScanner::ScanSuspicious() {
    auto all = Scan();
    std::vector<PciDeviceInfo> flagged;
    for (auto& d : all) {
        if (d.isFpga || d.isKnownDma)
            flagged.push_back(std::move(d));
    }
    return flagged;
}
