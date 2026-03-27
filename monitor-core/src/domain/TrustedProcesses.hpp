#pragma once
#include <string>
#include <algorithm>

namespace Trusted {

constexpr uint64_t kAccCreateThread  = 0x0002;
constexpr uint64_t kAccVmOperation   = 0x0008;
constexpr uint64_t kAccVmWrite       = 0x0020;
constexpr uint64_t kAccQueryInfo     = 0x0400;
constexpr uint64_t kAccQueryLimited  = 0x1000;
constexpr uint64_t kAccSynchronize   = 0x00100000;

inline bool IsBenignAccess(uint64_t access) {
    constexpr uint64_t kHarmless = kAccQueryLimited | kAccQueryInfo | kAccSynchronize;
    return (access & ~kHarmless) == 0;
}

inline bool IsDangerousAccess(uint64_t access) {
    if ((access & 0x001F0FFF) == 0x001F0FFF) return true;
    if ((access & (kAccVmWrite | kAccVmOperation)) == (kAccVmWrite | kAccVmOperation)) return true;
    if (access & kAccCreateThread) return true;
    return false;
}

inline std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline bool IsTrustedCaller(const char* name) {
    static const char* const kTrusted[] = {
        "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "sihost.exe",
        "fontdrvhost.exe", "dwm.exe", "conhost.exe",
        "explorer.exe", "searchhost.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "runtimebroker.exe",
        "applicationframehost.exe", "textinputhost.exe",
        "taskhostw.exe", "ctfmon.exe", "dllhost.exe", "backgroundtaskhost.exe",
        "taskmgr.exe", "procexp.exe", "procexp64.exe",
        "procmon.exe", "procmon64.exe", "perfmon.exe", "mmc.exe",
        "systemsettings.exe", "systemsettingsbroker.exe",
        "msmpeng.exe", "mpcmdrun.exe", "securityhealthservice.exe",
        "securityhealthhost.exe", "securityhealthsystray.exe",
        "nissrv.exe", "smartscreen.exe", "sgrmbroker.exe",
        "wuauclt.exe", "trustedinstaller.exe", "tiworker.exe",
        "musnotification.exe", "wsappx.exe",
        "wmiprvse.exe", "wmiapsrv.exe",
        "nvcontainer.exe", "nvdisplay.container.exe",
        "amdrsserv.exe", "igfxem.exe", "audiodg.exe",
    };

    std::string lower = ToLower(name);
    auto pos = lower.rfind('\\');
    if (pos != std::string::npos) lower = lower.substr(pos + 1);

    for (const auto* t : kTrusted) {
        if (lower == t) return true;
    }
    return false;
}

inline bool IsTrustedSigner(const std::string& signer) {
    if (signer.empty()) return false;
    std::string lower = ToLower(signer);

    static const char* const kSigners[] = {
        "microsoft", "google llc", "google inc", "mozilla corporation",
        "apple inc", "nvidia corporation", "advanced micro devices",
        "intel corporation", "intel(r)", "realtek semiconductor",
        "logitech", "corsair", "razer", "steelseries",
        "valve corp", "valve", "epic games", "riot games",
        "adobe", "oracle", "java", "zoom video communications",
        "discord inc", "spotify", "dropbox", "1password",
        "cloudflare", "github", "slack technologies", "obsproject", "elgato",
    };

    for (const auto* s : kSigners) {
        if (lower.find(s) != std::string::npos) return true;
    }
    return false;
}

inline bool ShouldSuppressProcessEvent(
    const char* callerName, const char*, uint64_t access, bool suspiciousCaller)
{
    if (suspiciousCaller) return false;
    if (IsBenignAccess(access)) return true;
    if (IsTrustedCaller(callerName) && !IsDangerousAccess(access)) return true;
    return false;
}

} // namespace Trusted
