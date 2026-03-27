#pragma once
#include <string_view>
#include "../core/EventTypes.hpp"

class Console {
public:
    enum class Color {
        Reset, Gray, White, Cyan, Green, Yellow, Red, Magenta, BrightRed
    };

    static void Init();
    static void Banner();
    static void Divider();
    static void Blank();

    static void Info    (std::string_view msg);
    static void Ok      (std::string_view msg);
    static void Warn    (std::string_view msg);
    static void Critical(std::string_view msg);
    static void Debug   (std::string_view msg);

    static void Event(const ProcessEvent& ev);

    static void Write  (Color c, std::string_view text);
    static void Writeln(Color c, std::string_view text);

private:
    static const char* Ansi(Color c);
    static std::string Timestamp();
    static std::string Pad(std::string_view s, size_t width);
};
