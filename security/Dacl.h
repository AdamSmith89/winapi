#pragma once

#include "defines.h"
#include "utility/defines.h"

namespace winapi::security
{
    class Dacl
    {

    };

    class DaclBuilder
    {
    public:
        static DaclBuilder Create() { return DaclBuilder(); }
        Dacl Build();

        DaclBuilder AddAccessAllowedAce(access_rights::Standard const accessMask, PSID pSid, ACLRevision const revision = ACLRevision::Revision);
    };
}