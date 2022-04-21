#include "pch.h"
#include "Dacl.h"

#include <doctest/doctest.h>

namespace winapi::security
{
    DaclBuilder DaclBuilder::AddAccessAllowedAce(access_rights::Standard const accessMask, PSID pSid, ACLRevision const revision/* = ACLRevision::Revision*/)
    {
        auto x = access_rights::File::AppendData;
        x ^= access_rights::Directory::AddFile;

        return *this;
    }

    Dacl DaclBuilder::Build()
    {
        return Dacl();
    }
}

TEST_CASE("test")
{
    CHECK(true == true);
    CHECK(true == false);
    CHECK(true == false);
}
