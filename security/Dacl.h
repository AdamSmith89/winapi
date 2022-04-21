#pragma once

#include "defines.h"
#include "utility/defines.h"

// NOT IMPLEMENTED
namespace winapi::security
{
    class DaclBuilder
    {
    public:
        static DaclBuilder Create() { return DaclBuilder(); }
        PACL Build();

        DaclBuilder AllowAccessFor(access_rights::Standard const accessMask, PSID pSid, ACLRevision const revision = ACLRevision::Revision);

    private:

    };
}