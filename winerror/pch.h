#pragma once

#ifdef NDEBUG
#define DOCTEST_CONFIG_DISABLE
#endif

// Windows Headers
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <Windows.h>

// C++ Headers
#include <functional>
#include <optional>
#include <string>
