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

    template<typename TOKEN_INFO_TYPE>
    std::optional<TOKEN_INFO_TYPE> GetTokenInformation(Handle const& handle, TokenInformationClass const type)
    {
        DWORD sizeRequired = 0;

        bool result = ::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(type), nullptr, 0, &sizeRequired);

        if (!result && winerror::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            std::unique_ptr<BYTE[]> pByteArray = std::make_unique<BYTE[]>(sizeRequired);
            if (::GetTokenInformation(handle.Get(), static_cast<TOKEN_INFORMATION_CLASS>(type), pByteArray.get(), sizeRequired, &sizeRequired))
            {
                TOKEN_INFO_TYPE tokenInfo = *reinterpret_cast<TOKEN_INFO_TYPE*>(pByteArray.get());
                return { tokenInfo };
            }
        }

        return {};
    }

#pragma region TOKEN_INFO_TYPE specializations
    // Template specialization of the different token information classes - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
    // Allows the user to call GetTokenInformation<TokenInformationClass::value>(handle) and not have to specify the structure type as well.
    template<auto T, typename = void> struct TOKEN_INFO_TYPE;
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::User>::type> { typedef TOKEN_USER type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Groups>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Privileges>::type> { typedef TOKEN_PRIVILEGES type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Owner>::type> { typedef TOKEN_OWNER type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::PrimaryGroup>::type> { typedef TOKEN_PRIMARY_GROUP type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::DefaultDacl>::type> { typedef TOKEN_DEFAULT_DACL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Source>::type> { typedef TOKEN_SOURCE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Type>::type> { typedef TOKEN_TYPE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::ImpersonationLevel>::type> { typedef SECURITY_IMPERSONATION_LEVEL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Statistics>::type> { typedef TOKEN_STATISTICS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::RestrictedSids>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::SessionId>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::GroupsAndPrivileges>::type> { typedef TOKEN_GROUPS_AND_PRIVILEGES type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::SessionReference>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::SandBoxInert>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::AuditPolicy>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Origin>::type> { typedef TOKEN_ORIGIN type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::ElevationType>::type> { typedef TOKEN_ELEVATION_TYPE type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::LinkedToken>::type> { typedef TOKEN_LINKED_TOKEN type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Elevation>::type> { typedef TOKEN_ELEVATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::HasRestrictions>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::AccessInformation>::type> { typedef TOKEN_ACCESS_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::VirtualizationAllowed>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::VirtualizationEnabled>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::IntegrityLevel>::type> { typedef TOKEN_MANDATORY_LABEL type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::UIAccess>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::MandatoryPolicy>::type> { typedef TOKEN_MANDATORY_POLICY type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::LogonSid>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::IsAppContainer>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::Capabilities>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::AppContainerSid>::type> { typedef TOKEN_APPCONTAINER_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::AppContainerNumber>::type> { typedef DWORD type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::UserClaimAttributes>::type> { typedef CLAIM_SECURITY_ATTRIBUTES_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::DeviceClaimAttributes>::type> { typedef CLAIM_SECURITY_ATTRIBUTES_INFORMATION type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::RestrictedUserClaimAttributes>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::RestrictedDeviceClaimAttributes>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::DeviceGroups>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::RestrictedDeviceGroups>::type> { typedef TOKEN_GROUPS type; };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::SecurityAttributes>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::IsRestricted>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::ProcessTrustLevel>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::PrivateNameSpace>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::SingletonAttributes>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::BnoIsolation>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::ChildProcessFlags>::type> { /* reserved */ };
    template<auto T> struct TOKEN_INFO_TYPE<T, typename std::enable_if<T == TokenInformationClass::IsLessPrivilegedAppContainer>::type> { /* reserved */ };
#pragma endregion

    template<TokenInformationClass T>
    std::optional<typename TOKEN_INFO_TYPE<T>::type> GetTokenInformation(Handle const& handle)
    {
        return GetTokenInformation<TOKEN_INFO_TYPE<T>::type>(handle, T);
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
}