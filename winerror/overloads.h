#pragma once

namespace winapi::winerror
{
    template<typename char_type>
    struct overloads;

    template<>
    struct overloads<char>
    {
        typedef LPSTR win_type;

        static std::function<DWORD(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*)> Format_Message()
        {
            return ::FormatMessageA;
        }
    };

    template<>
    struct overloads<wchar_t>
    {
        typedef LPWSTR win_type;

        static std::function<DWORD(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*)> Format_Message()
        {
            return ::FormatMessageW;
        }

    };
}