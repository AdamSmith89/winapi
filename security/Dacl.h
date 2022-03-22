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
        DaclBuilder AddAccessAllowedAce(ACLRevision const revision)
        {
            auto x = access_rights::File::AppendData;
            x ^= access_rights::Directory::AddFile;
        }
        //Dacl Build();
    };
}