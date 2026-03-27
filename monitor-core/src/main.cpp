#include "pch.hpp"
#include <thread>
#include <chrono>

#include "console/Console.hpp"
#include "core/Hooks.hpp"
#include "core/NtHooks.hpp"
#include "domain/DmaDetector.hpp"
#include "ipc/PipeClient.hpp"
#include "system/ProcessCache.hpp"
#include "system/DriverLoader.hpp"

static volatile bool g_running = true;

static BOOL WINAPI OnSignal(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_CLOSE_EVENT) {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

int main(int, char*[]) {
    Console::Init();
    Console::Banner();
    Console::Divider();

    SetConsoleCtrlHandler(OnSignal, TRUE);

    Console::Info("Connecting to backend pipe...");
    PipeClient::Instance().Connect();

    Console::Divider();
    Console::Info("[User-Mode Hooks]");
    if (!Hooks::Install()) {
        Console::Critical("kernel32 hooks failed.");
        return 1;
    }
    Console::Ok("kernel32 hooks installed (5 APIs).");

    if (!NtHooks::Install()) {
        Console::Warn("ntdll hooks failed — NT-layer monitoring disabled.");
    } else {
        Console::Ok("ntdll hooks installed (5 NT syscalls).");
    }

    Console::Divider();
    Console::Info("[Kernel Driver]");
    auto& driver = DriverLoader::Instance();
    if (driver.Load()) {
        driver.StartPolling();
        Console::Ok("Kernel driver loaded — ObCallbacks + ProcessNotify active.");
    } else {
        Console::Warn("Kernel driver not available — user-mode only.");
    }

    Console::Divider();
    Console::Info("[Hardware Security Scan]");
    DmaDetector::Instance().RunFullScan();
    DmaDetector::Instance().StartPeriodicScan(30000);

    Console::Divider();
    Console::Info("Monitoring started. Press Ctrl+C to stop.");
    Console::Blank();

    while (g_running)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Console::Blank();
    Console::Info("Shutting down...");
    DmaDetector::Instance().Stop();
    driver.Unload();
    NtHooks::Remove();
    Hooks::Remove();
    PipeClient::Instance().Disconnect();
    Console::Ok("Shutdown complete.");
    return 0;
}
