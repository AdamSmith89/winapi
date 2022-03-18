#pragma once

namespace winapi::security::identity
{
    template<typename char_type>
    struct overloads;

    template<>
    struct overloads<char>
    {
        static std::function<BOOL WINAPI(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE)> Logon_User()
        {
            return ::LogonUserA;
        }

        static std::function<BOOL SEC_ENTRY(EXTENDED_NAME_FORMAT, LPSTR, PULONG)> Get_UserNameEx()
        {
            return GetUserNameExA;
        }
    };

    template<>
    struct overloads<wchar_t>
    {
        static std::function<BOOL WINAPI(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE)> Logon_User()
        {
            return ::LogonUserW;
        }

        static std::function<BOOL SEC_ENTRY(EXTENDED_NAME_FORMAT, LPWSTR, PULONG)> Get_UserNameEx()
        {
            return GetUserNameExW;
        }
    };
}