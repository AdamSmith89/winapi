#pragma once

#include "defines.h"
#include "overloads.h"

#include "utility/Handle.h"
#include "winerror/Error.h"

namespace winapi::security::identity
{
    // Using _ to avoid collision with Windows macro
    template<typename char_type=char>
    std::optional<winapi::Handle> Logon_User(char_type const* username, char_type const* domain, char_type const* password, LogonType const type, LogonProvider const provider)
    {
        HANDLE phToken = nullptr;
        if (overloads<char_type>::Logon_User()(username, domain, password, static_cast<DWORD>(type), static_cast<DWORD>(provider), &phToken))
        {
            return winapi::Handle(phToken);
        }

        return {};
    }

    // Using _ to avoid collision with Windows macro
    // Requires linking against "Secur32.lib"
    template<typename char_type=char>
    std::optional<std::basic_string<char_type>> GetUserName_Ex(ExtendedNameFormat const format)
    {
        unsigned long size = 0;

        if (!overloads<char_type>::Get_UserNameEx()(static_cast<EXTENDED_NAME_FORMAT>(format), nullptr, &size) &&
            GetLastError() == ERROR_MORE_DATA)
        {
            std::basic_string<char_type> name;
            name.resize(size);

            if (overloads<char_type>::Get_UserNameEx()(static_cast<EXTENDED_NAME_FORMAT>(format), name.data(), &size))
            {
                return name;
            }
        }

        return {};
    }

    template<typename TokenInformationType>
    std::optional<TokenInformationType> GetTokenInformation(Handle const& handle, TokenInformationClass const type)
    {
        std::unique_ptr<TokenInformationType> pTokenInfo = nullptr;
        DWORD sizeRequired = 0;

        bool result = ::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(type), nullptr, 0, &sizeRequired);

        if (!result && winerror::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            void* pRaw = operator new(sizeRequired);
            if (::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(type), pRaw, sizeRequired, &sizeRequired))
            {
                pTokenInfo.reset(static_cast<TokenInformationType*>(pRaw));
                TokenInformationType tokenInfo = *pTokenInfo.release();
                return { tokenInfo };
            }
        }

        return {};
    }
}