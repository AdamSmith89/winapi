#include "pch.h"

#include "security/identity.h"
#include "utility/Handle.h"
#include "winerror/Error.h"

using namespace winapi;

// Use this command line app to test API wrappers
int main()
{
    using namespace security::identity;

    auto processHandle = Handle(GetCurrentProcessToken());
    auto tokenUser = GetTokenInformation<TokenInformationClass::User>(processHandle);
    auto tokenType = GetTokenInformation<TokenInformationClass::Type>(processHandle);
    auto tokenGroups = GetTokenInformation<TokenInformationClass::Groups>(processHandle);
    //auto tokenGroups = GetTokenInformation<TokenInformationClass::SessionReference>(processHandle);
}
