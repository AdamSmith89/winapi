#pragma once

#include <type_traits>

// This file contains a templated implementation of the c++ concept "BitmaskType". See:
// http://en.cppreference.com/w/cpp/concept/BitmaskType
// This leverages SFINAE to ensure invalid enums do not use the overloaded functions. It should be used with an implementation of an "enum class". Usage:
// Create an enum class with valid bitmask values. Call ENABLE_GENERIC_BITMASK_TYPE_OPS to
// enable the operations for the enum class. enum classes that are not registered using ENABLE_GENERIC_BITMASK_TYPE_OPS
// will then not fall into the overloaded functions.

template<typename T>
struct GenericBitmaskTypeOps
{
    static const bool bEnabled = false;
};

template<typename T>
struct SimilarBitmaskTypeOps
{
    static const bool bEnabled = false;
};

#define ENABLE_GENERIC_BITMASK_TYPE_OPS(x) \
    template<> \
    struct GenericBitmaskTypeOps<x> \
    { \
        static const bool bEnabled = true; \
    };

// Use to allow different enums with the same underlying type to have bitwise operations enabled
#define ENABLE_SIMILAR_BITMASK_TYPE_OPS(x) \
    template<> \
    struct SimilarBitmaskTypeOps<x> \
    { \
        static const bool bEnabled = true; \
    };

#pragma region GENERIC_BITMASK_OPS
template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T> operator&(T lhs, T rhs)
{
    return (static_cast<T>(static_cast<std::underlying_type<T>::type>(lhs) & static_cast<std::underlying_type<T>::type>(rhs)));
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T> operator|(T lhs, T rhs)
{
    return (static_cast<T>(static_cast<std::underlying_type<T>::type>(lhs) | static_cast<std::underlying_type<T>::type>(rhs)));
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T> operator^(T lhs, T rhs)
{
    return (static_cast<T>(static_cast<std::underlying_type<T>::type>(lhs) ^ static_cast<std::underlying_type<T>::type>(rhs)));
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T> operator~(T lhs)
{
    return (static_cast<T>(~static_cast<std::underlying_type<T>::type>(lhs)));
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T>& operator&=(T& lhs, T rhs)
{
    lhs = lhs & rhs;
    return (lhs);
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T>& operator|=(T& lhs, T rhs)
{
    lhs = lhs | rhs;
    return (lhs);
}

template<typename T>
inline constexpr std::enable_if_t<GenericBitmaskTypeOps<T>::bEnabled, T>& operator^=(T& lhs, T rhs)
{
    lhs = lhs ^ rhs;
    return (lhs);
}
#pragma endregion

#pragma region SIMILAR_BITMASK_OPS

// Can the std::enable_if_t checks be simplified or pulled out?

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled && SimilarBitmaskTypeOps<T2>::bEnabled && std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, std::underlying_type_t<T1>>
    operator&(T1 lhs, T2 rhs)
{
    return (static_cast<std::underlying_type_t<T1>>(static_cast<std::underlying_type_t<T1>>(lhs) & static_cast<std::underlying_type_t<T2>>(rhs)));
}

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled&& SimilarBitmaskTypeOps<T2>::bEnabled&& std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, std::underlying_type_t<T1>>
    operator|(T1 lhs, T2 rhs)
{
    return (static_cast<std::underlying_type_t<T1>>(static_cast<std::underlying_type_t<T1>>(lhs) | static_cast<std::underlying_type_t<T2>>(rhs)));
}

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled&& SimilarBitmaskTypeOps<T2>::bEnabled&& std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, std::underlying_type_t<T1>>
    operator^(T1 lhs, T2 rhs)
{
    return (static_cast<std::underlying_type_t<T1>>(static_cast<std::underlying_type_t<T1>>(lhs) ^ static_cast<std::underlying_type_t<T2>>(rhs)));
}

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled&& SimilarBitmaskTypeOps<T2>::bEnabled&& std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, T1>
    & operator&=(T1& lhs, T2 rhs)
{
    lhs = static_cast<T1>(lhs & rhs);
    return (lhs);
}

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled&& SimilarBitmaskTypeOps<T2>::bEnabled&& std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, T1>
    & operator|=(T1& lhs, T2 rhs)
{
    lhs = static_cast<T1>(lhs | rhs);
    return (lhs);
}

template<typename T1, typename T2>
inline constexpr
    std::enable_if_t<SimilarBitmaskTypeOps<T1>::bEnabled&& SimilarBitmaskTypeOps<T2>::bEnabled&& std::is_same_v<std::underlying_type_t<T1>, std::underlying_type_t<T2>>, T1>
    & operator^=(T1& lhs, T2 rhs)
{
    lhs = static_cast<T1>(lhs ^ rhs);
    return (lhs);
}
#pragma endregion