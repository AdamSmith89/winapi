#pragma once

#include "overloads.h"
#include "utility/Handle.h"

namespace security::identity
{
    enum class LogonType
    {
        Interactive = LOGON32_LOGON_INTERACTIVE,                // This logon type is intended for users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process. This logon type has the additional expense of caching logon information for disconnected operations; therefore, it is inappropriate for some client/server applications, such as a mail server.
        Network = LOGON32_LOGON_NETWORK,                        // This logon type is intended for high performance servers to authenticate plaintext passwords. The LogonUser function does not cache credentials for this logon type.
        Batch = LOGON32_LOGON_BATCH,                            // This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention. This type is also for higher performance servers that process many plaintext authentication attempts at a time, such as mail or web servers.
        Service = LOGON32_LOGON_SERVICE,                        // Indicates a service-type logon. The account provided must have the service privilege enabled.
        Network_ClearText = LOGON32_LOGON_NETWORK_CLEARTEXT,    // This logon type preserves the name and password in the authentication package, which allows the server to make connections to other network servers while impersonating the client. A server can accept plaintext credentials from a client, call LogonUser, verify that the user can access the system across the network, and still communicate with other servers.
        New_Credentials = LOGON32_LOGON_NEW_CREDENTIALS         // This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections. This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
    };

    enum class LogonProvider
    {
        Default = LOGON32_PROVIDER_DEFAULT, // Use the standard logon provider for the system.
        WinNT50 = LOGON32_PROVIDER_WINNT50, // Use the negotiate logon provider.
        WinNT40 = LOGON32_PROVIDER_WINNT40  // Use the NTLM logon provider.
    };

    // Using _ to avoid collision with Windows macro
    template<typename char_type>
    std::optional<winapi::Handle> Logon_User(char_type const* username, char_type const* domain, char_type const* password, LogonType const type, LogonProvider const provider)
    {
        HANDLE phToken = nullptr;
        if (overloads<char_type>::Logon_User()(username, domain, password, static_cast<DWORD>(type), static_cast<DWORD>(provider), &phToken))
        {
            return winapi::Handle(phToken);
        }

        return {};
    }

    enum class ExtendedNameFormat
    {
        Unknown = NameUnknown,
        FullyQualifiedDN = NameFullyQualifiedDN,
        SamCompatible = NameSamCompatible,
        Display = NameDisplay,
        UniqueId = NameUniqueId,
        Canonical = NameCanonical,
        UserPrincipal = NameUserPrincipal,
        CanonicalEx = NameCanonicalEx,
        ServicePrincipal = NameServicePrincipal,
        DnsDomain = NameDnsDomain,
        GivenName = NameGivenName,
        Surname = NameSurname
    };

    // Using _ to avoid collision with Windows macro
    // Requires linking against "Secur32.lib"
    template<typename char_type>
    std::optional<std::basic_string<char_type>> Get_UserNameEx(ExtendedNameFormat const format)
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
}