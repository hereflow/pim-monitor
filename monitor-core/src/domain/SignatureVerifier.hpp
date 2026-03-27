#pragma once
#include <string>
#include <cstdint>

enum class SignatureStatus : uint8_t {
    Valid      = 0,
    Invalid    = 1,
    Unsigned   = 2,
    Expired    = 3,
    Untrusted  = 4,
    Error      = 5,
};

struct SignatureInfo {
    SignatureStatus status;
    std::string     signer;
    std::string     issuer;
    std::string     serial;
    bool            isTrusted;
};

inline const char* SignatureStatusName(SignatureStatus s) {
    switch (s) {
        case SignatureStatus::Valid:     return "valid";
        case SignatureStatus::Invalid:   return "invalid";
        case SignatureStatus::Unsigned:  return "unsigned";
        case SignatureStatus::Expired:   return "expired";
        case SignatureStatus::Untrusted: return "untrusted";
        case SignatureStatus::Error:     return "error";
        default:                         return "unknown";
    }
}

class SignatureVerifier {
public:
    static SignatureInfo Verify(const std::string& filePath);
    static SignatureInfo VerifyPid(uint32_t pid);

private:
    static std::string GetProcessPath(uint32_t pid);
    static std::string ExtractSignerName(const std::string& filePath);
};
