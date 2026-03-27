#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <intrin.h>

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include "MinHook.h"
