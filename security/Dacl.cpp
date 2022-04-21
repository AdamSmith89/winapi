#include "pch.h"
#include "Dacl.h"

#include <doctest/doctest.h>

// NOT IMPLEMENTED

namespace winapi::security
{
    DaclBuilder DaclBuilder::AllowAccessFor(access_rights::Standard const accessMask, PSID pSid, ACLRevision const revision/* = ACLRevision::Revision*/)
    {
        auto x = access_rights::File::AppendData;
        x ^= access_rights::Directory::AddFile;

        return *this;
    }

    PACL DaclBuilder::Build()
    {
        return nullptr;
    }
}

TEST_SUITE_BEGIN("DaclBuilder");
TEST_CASE("AllowAccessFor adds ace correctly")
{
    using namespace winapi;
    using namespace winapi::security;

    DaclBuilder daclBuilder = DaclBuilder::Create();

    auto dacl = daclBuilder
        .AllowAccessFor(access_rights::Standard::All, nullptr)
        .Build();
}
TEST_SUITE_END();
