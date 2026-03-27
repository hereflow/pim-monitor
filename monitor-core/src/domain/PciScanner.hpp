#pragma once
#include <cstdint>
#include <vector>
#include <string>

struct PciDeviceInfo {
    uint16_t    vendorId;
    uint16_t    deviceId;
    uint16_t    subVendorId;
    uint16_t    subDeviceId;
    std::string description;
    std::string location;
    std::string instanceId;
    std::string hardwareId;
    bool        isFpga;
    bool        isKnownDma;
    std::string threatReason;
};

class PciScanner {
public:
    static PciScanner& Instance();

    std::vector<PciDeviceInfo> Scan();
    std::vector<PciDeviceInfo> ScanSuspicious();

private:
    PciScanner() = default;

    struct KnownDmaEntry {
        uint16_t    vendorId;
        uint16_t    deviceId;
        const char* name;
    };

    static const KnownDmaEntry kDmaDevices[];
    static const uint16_t      kFpgaVendors[];

    bool IsFpgaVendor(uint16_t vid) const;
    bool IsKnownDma(uint16_t vid, uint16_t did, std::string& outReason) const;
    bool ParseHardwareIds(const std::string& hwid, uint16_t& vid, uint16_t& did,
                          uint16_t& subVid, uint16_t& subDid) const;
};
