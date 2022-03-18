#include "pch.h"

#include "security/identity.h"
#include "winerror/Error.h"

using namespace winapi;

// Use this command line app to test API wrappers
int main()
{
    using namespace security::identity;

    auto usernameA = GetUserName_Ex(ExtendedNameFormat::UserPrincipal);
    auto error = winerror::GetLastError();
    if (error.Failed())
    {
        auto errorStr = error.AsString();
    }
}
