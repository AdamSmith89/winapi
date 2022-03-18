#include "pch.h"

#include "identity.h"

namespace security::identity
{
    std::optional<winapi::Handle> Logon_User(std::string const& username, std::optional<std::string> const& domain, std::optional<std::string> const& password, LogonType const type, LogonProvider const provider)
    {
        LPCSTR szDomain = domain ? domain->c_str() : nullptr;
        LPCSTR szPassword = password ? password->c_str() : nullptr;

        HANDLE phToken = nullptr;
        if (::LogonUserA(username.c_str(), szDomain, szPassword, static_cast<DWORD>(type), static_cast<DWORD>(provider), &phToken))
        {
            return { winapi::Handle(phToken) };
        }
        
        return {};
    }
}
