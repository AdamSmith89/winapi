#pragma once

#include "defines.h"
#include "overloads.h"

#include "utility/Handle.h"
#include "winerror/Error.h"

namespace winapi::security::identity
{
    // Using _ to avoid collision with Windows macro
    
    /// <summary>
    /// Attempts to log a user on to the local computer. The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer. You specify the user with a user name and domain and authenticate the user with a plaintext password. If the function succeeds, you receive a handle to a token that represents the logged-on user. You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
    /// Using _ to avoid collision with Windows macro.
    /// </summary>
    /// <typeparam name="char_type">Character type of return value. Defaults to <c>char</c></typeparam>
    /// <param name="username">- Specifies the name of the user. This is the name of the user account to log on to. If you use the user principal name (UPN) format, User@DNSDomainName, the lpszDomain parameter must be NULL.</param>
    /// <param name="domain">- Optionally specifies the name of the domain or server whose account database contains the username account. If this parameter is NULL, the user name must be specified in UPN format. If this parameter is ".", the function validates the account by using only the local account database.</param>
    /// <param name="password">- Optionally specifies the plaintext password for the user account specified by username. When you have finished using the password, clear the password from memory by calling the SecureZeroMemory function.</param>
    /// <param name="type">- The type of logon operation to perform.</param>
    /// <param name="provider">- Specifies the logon provider.</param>
    /// <returns>Handle to a token that represents the specified user if successful. std::nullopt if not.</returns>
    /// <remarks>Requires linking against Advapi32.lib</remarks>
    template<typename char_type=char>
    std::optional<winapi::Handle> Logon_User(std::basic_string_view<char_type> const username, std::optional<std::basic_string_view<char_type>> const domain, std::optional<std::basic_string_view<char_type>> const password, LogonType const type, LogonProvider const provider)
    {
        HANDLE phToken = nullptr;
        char_type const* pDomain = domain ? domain->data() : nullptr;
        char_type const* pPassword = password ? password->data() : nullptr;
        if (overloads<char_type>::Logon_User()(username.data(), pDomain, pPassword, static_cast<DWORD>(type), static_cast<DWORD>(provider), &phToken))
        {
            return winapi::Handle(phToken);
        }

        return {};
    }

#pragma region TOKEN_INFO_TYPE specializations
    // Template specialization of the different token information classes - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
    // Allows the user to call GetTokenInformation<TokenInformationClass::value>(handle) and not have to specify the structure type as well.
    template<auto T, typename = void> struct TOKEN_INFO_TYPE;
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::User>> { typedef TOKEN_USER type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Groups>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Privileges>> { typedef TOKEN_PRIVILEGES type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Owner>> { typedef TOKEN_OWNER type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::PrimaryGroup>> { typedef TOKEN_PRIMARY_GROUP type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::DefaultDacl>> { typedef TOKEN_DEFAULT_DACL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Source>> { typedef TOKEN_SOURCE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Type>> { typedef TOKEN_TYPE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::ImpersonationLevel>> { typedef SECURITY_IMPERSONATION_LEVEL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Statistics>> { typedef TOKEN_STATISTICS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::RestrictedSids>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::SessionId>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::GroupsAndPrivileges>> { typedef TOKEN_GROUPS_AND_PRIVILEGES type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::SessionReference>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::SandBoxInert>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::AuditPolicy>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Origin>> { typedef TOKEN_ORIGIN type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::ElevationType>> { typedef TOKEN_ELEVATION_TYPE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::LinkedToken>> { typedef TOKEN_LINKED_TOKEN type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Elevation>> { typedef TOKEN_ELEVATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::HasRestrictions>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::AccessInformation>> { typedef TOKEN_ACCESS_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::VirtualizationAllowed>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::VirtualizationEnabled>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::IntegrityLevel>> { typedef TOKEN_MANDATORY_LABEL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::UIAccess>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::MandatoryPolicy>> { typedef TOKEN_MANDATORY_POLICY type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::LogonSid>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::IsAppContainer>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::Capabilities>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::AppContainerSid>> { typedef TOKEN_APPCONTAINER_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::AppContainerNumber>> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::UserClaimAttributes>> { typedef CLAIM_SECURITY_ATTRIBUTES_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::DeviceClaimAttributes>> { typedef CLAIM_SECURITY_ATTRIBUTES_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::RestrictedUserClaimAttributes>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::RestrictedDeviceClaimAttributes>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::DeviceGroups>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::RestrictedDeviceGroups>> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::SecurityAttributes>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::IsRestricted>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::ProcessTrustLevel>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::PrivateNameSpace>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::SingletonAttributes>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::BnoIsolation>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::ChildProcessFlags>> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if_t<T == TokenInformationClass::IsLessPrivilegedAppContainer>> { /* reserved */ };
#pragma endregion

    /// <summary>
    /// Retrieves a specified type of information about an access token. The calling process must have appropriate access rights to obtain the information.
    /// </summary>
    /// <typeparam name="TokenInformationClass">Specifies the type of information the function retrieves.</typeparam>
    /// <param name="handle">A handle to an access token from which information is retrieved. If TokenInformationClass specifies Source, the handle must have TOKEN_QUERY_SOURCE access. For all other TokenInformationClass values, the handle must have TOKEN_QUERY access.</param>
    /// <returns>Structure that represents requested data, whose type is derived from the TokenInformationClass template parameter, if successful. std::nullopt if not.</returns>
    /// <remarks>Requires linking against Advapi32.lib</remarks>
    template<TokenInformationClass T>
    std::optional<typename TOKEN_INFO_TYPE<T>::type> GetTokenInformation(Handle const& handle)
    {
        DWORD sizeRequired = 0;

        bool result = ::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(T), nullptr, 0, &sizeRequired);

        if (!result && winerror::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            std::unique_ptr<BYTE[]> pByteArray = std::make_unique<BYTE[]>(sizeRequired);
            if (::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(T), pByteArray.get(), sizeRequired, &sizeRequired))
            {
                auto tokenInfo = *reinterpret_cast<TOKEN_INFO_TYPE<T>::type*>(pByteArray.get());
                return { tokenInfo };
            }
        }

        return {};
    }

    /// <summary>
    /// Retrieves the name of the user or other security principal associated with the calling thread. You can specify the format of the returned name.
    /// If the thread is impersonating a client, GetUserNameEx returns the name of the client.
    /// Using _ to avoid collision with Windows macro.
    /// </summary>
    /// <typeparam name="char_type">Character type of return value. Defaults to <c>char</c></typeparam>
    /// <param name="format"> - The format of the name. It cannot be Unknown. If the user account is not in a domain, only SamCompatible is supported.</param>
    /// <returns>User name if successful. std::nullopt if not.</returns>
    /// <remarks>Requires linking against Secur32.lib</remarks>
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
}
