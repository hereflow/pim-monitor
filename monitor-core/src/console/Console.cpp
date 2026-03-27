#include "pch.hpp"
#include <cstdio>
#include "Console.hpp"

void Console::Init() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

const char* Console::Ansi(Color c) {
    switch (c) {
        case Color::Reset:     return "\033[0m";
        case Color::Gray:      return "\033[90m";
        case Color::White:     return "\033[97m";
        case Color::Cyan:      return "\033[96m";
        case Color::Green:     return "\033[92m";
        case Color::Yellow:    return "\033[93m";
        case Color::Red:       return "\033[91m";
        case Color::Magenta:   return "\033[95m";
        case Color::BrightRed: return "\033[1;31m";
        default:               return "\033[0m";
    }
}

std::string Console::Timestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

std::string Console::Pad(std::string_view s, size_t width) {
    std::string out(s);
    if (out.size() < width) out.append(width - out.size(), ' ');
    return out;
}

void Console::Write(Color c, std::string_view text) {
    printf("%s%.*s%s", Ansi(c), (int)text.size(), text.data(), Ansi(Color::Reset));
}

void Console::Writeln(Color c, std::string_view text) {
    printf("%s%.*s%s\n", Ansi(c), (int)text.size(), text.data(), Ansi(Color::Reset));
}

void Console::Banner() {
    Blank();
    Writeln(Color::Cyan,  "  ██████╗ ██╗███╗   ███╗");
    Writeln(Color::Cyan,  "  ██╔══██╗██║████╗ ████║");
    Writeln(Color::Cyan,  "  ██████╔╝██║██╔████╔██║");
    Writeln(Color::Cyan,  "  ██╔═══╝ ██║██║╚██╔╝██║");
    Writeln(Color::Cyan,  "  ██║     ██║██║ ╚═╝ ██║");
    Writeln(Color::Gray,  "  Process Integrity Monitor  v1.0");
    Blank();
}

void Console::Divider() {
    Writeln(Color::Gray, "  ─────────────────────────────────────────────────────");
}

void Console::Blank() { printf("\n"); }

void Console::Info(std::string_view msg) {
    Write(Color::Gray,  "  " + Timestamp() + "  ");
    Write(Color::Cyan,  "INFO  ");
    Writeln(Color::White, msg);
}

void Console::Ok(std::string_view msg) {
    Write(Color::Gray,  "  " + Timestamp() + "  ");
    Write(Color::Green, "OK    ");
    Writeln(Color::White, msg);
}

void Console::Warn(std::string_view msg) {
    Write(Color::Gray,   "  " + Timestamp() + "  ");
    Write(Color::Yellow, "WARN  ");
    Writeln(Color::White, msg);
}

void Console::Critical(std::string_view msg) {
    Write(Color::Gray,      "  " + Timestamp() + "  ");
    Write(Color::BrightRed, "CRIT  ");
    Writeln(Color::Red, msg);
}

void Console::Debug(std::string_view msg) {
    Write(Color::Gray,    "  " + Timestamp() + "  ");
    Write(Color::Magenta, "DBG   ");
    Writeln(Color::Gray, msg);
}

void Console::Event(const ProcessEvent& ev) {
    Color c = Color::Cyan;
    if (ev.suspiciousCaller)           c = Color::BrightRed;
    else if (ev.severity == Severity::Critical) c = Color::Red;
    else if (ev.severity == Severity::Warning)  c = Color::Yellow;

    Write(Color::Gray, "  " + Timestamp() + "  ");
    Write(c,           Pad(ApiTypeName(ev.api), 24));
    Write(Color::Gray, "[" + std::string(OriginName(ev.origin)) + "] ");
    Write(Color::White, Pad(ev.callerName, 22));
    Write(Color::Gray, " -> ");
    Writeln(Color::White, ev.targetName);
}
