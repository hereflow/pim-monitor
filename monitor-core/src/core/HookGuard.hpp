#pragma once

namespace HookGuard {
    inline thread_local bool Active = false;

    struct Scope {
        Scope()  { Active = true;  }
        ~Scope() { Active = false; }
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;
    };
}
