#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <mutex>

class ProcessCache {
public:
    static ProcessCache& Instance() {
        static ProcessCache inst;
        return inst;
    }

    std::string GetName(uint32_t pid) {
        if (pid == 0) return "[Idle]";
        if (pid == 4) return "[System]";
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(pid);
        if (it != cache_.end()) return it->second;
        std::string name = Query(pid);
        cache_[pid] = name;
        return name;
    }

    void Invalidate(uint32_t pid) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.erase(pid);
    }

private:
    std::string Query(uint32_t pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return "[pid:" + std::to_string(pid) + "]";
        char buf[MAX_PATH]{};
        DWORD sz = MAX_PATH;
        if (!QueryFullProcessImageNameA(h, 0, buf, &sz)) {
            CloseHandle(h);
            return "[restricted]";
        }
        CloseHandle(h);
        std::string full(buf);
        auto pos = full.rfind('\\');
        return (pos != std::string::npos) ? full.substr(pos + 1) : full;
    }

    std::unordered_map<uint32_t, std::string> cache_;
    std::mutex mutex_;
};

inline uint64_t NowMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uli.QuadPart - 116444736000000000ULL) / 10000ULL;
}
