#include "pch.h"

#include "security/identity.h"

// Use this command line app to test API wrappers
int main()
{
    using namespace security::identity;

    auto userToken = Logon_User("username", "domain", "password", LogonType::Interactive, LogonProvider::Default);
}
