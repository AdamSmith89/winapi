#pragma once

#ifdef NDEBUG
#define DOCTEST_CONFIG_DISABLE
#endif

// Windows Headers
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX                        // Remove min/max macros to avoid conflicts with std::min/max
#include <Windows.h>
#define SECURITY_WIN32
#include <security.h>

// C++ Headers
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
