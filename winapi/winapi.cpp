#include "pch.h"

#include "security/identity.h"
#include "utility/Handle.h"
#include "winerror/Error.h"

using namespace winapi;

// Use this command line app to test API wrappers
int main()
{
    using namespace security::identity;
    using namespace std::literals;

    auto processHandle = Handle(GetCurrentProcessToken());
    auto tokenUser = GetTokenInformation<TokenInformationClass::User>(processHandle);
    auto tokenType = GetTokenInformation<TokenInformationClass::Type>(processHandle);
    auto tokenGroups = GetTokenInformation<TokenInformationClass::Groups>(processHandle);

    // Showing alternative ways to instantiate a std::optional for domain and password fields
    auto userToken = Logon_User("username"sv, { "domain"sv }, std::make_optional("password"sv), LogonType::Interactive, LogonProvider::Default);
}
