#pragma once

namespace winapi::security
{
    enum class ACLRevision
    {
        Revision = ACL_REVISION,
        Revision_DS = ACL_REVISION_DS
    };

    enum class ExtendedNameFormat
    {
        Unknown = NameUnknown,                      // An unknown name type.
        FullyQualifiedDN = NameFullyQualifiedDN,    // The fully qualified distinguished name (for example, CN=Jeff Smith,OU=Users,DC=Engineering,DC=Microsoft,DC=Com).
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

    enum class LogonProvider
    {
        Default = LOGON32_PROVIDER_DEFAULT, // Use the standard logon provider for the system.
        WinNT50 = LOGON32_PROVIDER_WINNT50, // Use the negotiate logon provider.
        WinNT40 = LOGON32_PROVIDER_WINNT40  // Use the NTLM logon provider.
    };

    enum class LogonType
    {
        Interactive = LOGON32_LOGON_INTERACTIVE,                // This logon type is intended for users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process. This logon type has the additional expense of caching logon information for disconnected operations; therefore, it is inappropriate for some client/server applications, such as a mail server.
        Network = LOGON32_LOGON_NETWORK,                        // This logon type is intended for high performance servers to authenticate plaintext passwords. The LogonUser function does not cache credentials for this logon type.
        Batch = LOGON32_LOGON_BATCH,                            // This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention. This type is also for higher performance servers that process many plaintext authentication attempts at a time, such as mail or web servers.
        Service = LOGON32_LOGON_SERVICE,                        // Indicates a service-type logon. The account provided must have the service privilege enabled.
        Network_ClearText = LOGON32_LOGON_NETWORK_CLEARTEXT,    // This logon type preserves the name and password in the authentication package, which allows the server to make connections to other network servers while impersonating the client. A server can accept plaintext credentials from a client, call LogonUser, verify that the user can access the system across the network, and still communicate with other servers.
        New_Credentials = LOGON32_LOGON_NEW_CREDENTIALS         // This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections. This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
    };

    enum class TokenInformationClass
    {
        User = TokenUser,
        Groups = TokenGroups,
        Privileges = TokenPrivileges,
        Owner = TokenOwner,
        PrimaryGroup = TokenPrimaryGroup,
        DefaultDacl = TokenDefaultDacl,
        Source = TokenSource,
        Type = TokenType,
        ImpersonationLevel = TokenImpersonationLevel,
        Statistics = TokenStatistics,
        RestrictedSids = TokenRestrictedSids,
        SessionId = TokenSessionId,
        GroupsAndPrivileges = TokenGroupsAndPrivileges,
        SessionReference = TokenSessionReference,   /* Reserved */
        SandBoxInert = TokenSandBoxInert,
        AuditPolicy = TokenAuditPolicy,             /* Reserved */
        Origin = TokenOrigin,
        ElevationType = TokenElevationType,
        LinkedToken = TokenLinkedToken,
        Elevation = TokenElevation,
        HasRestrictions = TokenHasRestrictions,
        AccessInformation = TokenAccessInformation,
        VirtualizationAllowed = TokenVirtualizationAllowed,
        VirtualizationEnabled = TokenVirtualizationEnabled,
        IntegrityLevel = TokenIntegrityLevel,
        UIAccess = TokenUIAccess,
        MandatoryPolicy = TokenMandatoryPolicy,
        LogonSid = TokenLogonSid,
        IsAppContainer = TokenIsAppContainer,
        Capabilities = TokenCapabilities,
        AppContainerSid = TokenAppContainerSid,
        AppContainerNumber = TokenAppContainerNumber,
        UserClaimAttributes = TokenUserClaimAttributes,
        DeviceClaimAttributes = TokenDeviceClaimAttributes,
        RestrictedUserClaimAttributes = TokenRestrictedUserClaimAttributes,
        RestrictedDeviceClaimAttributes = TokenRestrictedDeviceClaimAttributes,
        DeviceGroups = TokenDeviceGroups,
        RestrictedDeviceGroups = TokenRestrictedDeviceGroups,
        SecurityAttributes = TokenSecurityAttributes,
        IsRestricted = TokenIsRestricted,
        ProcessTrustLevel = TokenProcessTrustLevel,
        PrivateNameSpace = TokenPrivateNameSpace,
        SingletonAttributes = TokenSingletonAttributes,
        BnoIsolation = TokenBnoIsolation,
        ChildProcessFlags = TokenChildProcessFlags,
        IsLessPrivilegedAppContainer = TokenIsLessPrivilegedAppContainer,
        IsSandboxed = TokenIsSandboxed,
        Max = MaxTokenInfoClass
    };
}
