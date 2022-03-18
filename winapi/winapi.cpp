#include "pch.h"

#include "security/identity.h"

// Use this command line app to test API wrappers
int main()
{
    using namespace security::identity;

    auto usernameA = Get_UserNameEx<char>(ExtendedNameFormat::UserPrincipal);
    auto usernameW = Get_UserNameEx<wchar_t>(ExtendedNameFormat::UserPrincipal);
}
