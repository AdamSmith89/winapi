#include "pch.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

#include "security/Dacl.h"
#include "security/identity.h"
#include "utility/Handle.h"
#include "winerror/Error.h"

 //Use this command line app to test API wrappers
int main(int argc, char** argv)
{
    // Tests will only run in debug builds
    // For doctest arguments refer to https://github.com/doctest/doctest/blob/master/doc/markdown/commandline.md
    doctest::Context context(argc, argv);
    int res = context.run();

    if (context.shouldExit()) // important - query flags (and --exit) rely on the user doing this
        return res;          // propagate the result of the tests

    using namespace winapi;
    using namespace security;
    using namespace security::identity;
    using namespace std::literals;

    auto processHandle = Handle(GetCurrentProcessToken());
    auto tokenUser = GetTokenInformation<TokenInformationClass::User>(processHandle);
    auto tokenType = GetTokenInformation<TokenInformationClass::Type>(processHandle);
    auto tokenGroups = GetTokenInformation<TokenInformationClass::Groups>(processHandle);

    // Showing alternative ways to instantiate a std::optional for domain and password fields
    auto userToken = Logon_User("username"sv, { "domain"sv }, std::make_optional("password"sv), LogonType::Interactive, LogonProvider::Default);

    auto dacl = DaclBuilder::Create()
        .AddAccessAllowedAce(access_rights::Standard::All, nullptr)
        .Build();
}
