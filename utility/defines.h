#pragma once

#include "GenericBitmaskType.h"

namespace winapi::access_rights
{
    enum class Standard : unsigned int
    {
        Delete = DELETE,
        ReadControl = READ_CONTROL,
        WriteDAC = WRITE_DAC,
        WriteOwner = WRITE_OWNER,
        Synchronize = SYNCHRONIZE,
        Read = STANDARD_RIGHTS_READ,
        Write = STANDARD_RIGHTS_WRITE,
        Execute = STANDARD_RIGHTS_EXECUTE,
        All = STANDARD_RIGHTS_ALL,
        SpecificAll = SPECIFIC_RIGHTS_ALL,
        MaximumAllowed = MAXIMUM_ALLOWED
    };
    ENABLE_GENERIC_BITMASK_TYPE_OPS(Standard);
    ENABLE_SIMILAR_BITMASK_TYPE_OPS(Standard);

    enum class Generic : unsigned int
    {
        Read = GENERIC_READ,
        Write = GENERIC_WRITE,
        Execute = GENERIC_EXECUTE,
        All = GENERIC_ALL
    };
    ENABLE_GENERIC_BITMASK_TYPE_OPS(Generic);
    ENABLE_SIMILAR_BITMASK_TYPE_OPS(Generic);

    enum class File : unsigned int
    {
        ReadData = FILE_READ_DATA,
        WriteData = FILE_WRITE_DATA,
        AppendData = FILE_APPEND_DATA,
        ReadEA = FILE_READ_EA,
        WriteEA = FILE_WRITE_EA,
        Execute = FILE_EXECUTE,
        ReadAttributes = FILE_READ_ATTRIBUTES,
        WriteAttributes = FILE_WRITE_ATTRIBUTES
    };
    ENABLE_GENERIC_BITMASK_TYPE_OPS(File);
    ENABLE_SIMILAR_BITMASK_TYPE_OPS(File);

    enum class Directory : unsigned int
    {
        List = FILE_LIST_DIRECTORY,
        AddFile = FILE_ADD_FILE,
        AddSubDirectory = FILE_ADD_SUBDIRECTORY,
        ReadEA = FILE_READ_EA,
        WriteEA = FILE_WRITE_EA,
        Traverse = FILE_TRAVERSE,
        DeleteChild = FILE_DELETE_CHILD,
        ReadAttributes = FILE_READ_ATTRIBUTES,
        WriteAttributes = FILE_WRITE_ATTRIBUTES
    };
    ENABLE_GENERIC_BITMASK_TYPE_OPS(Directory);
    ENABLE_SIMILAR_BITMASK_TYPE_OPS(Directory);

    enum class Pipe : unsigned int
    {
        ReadData = FILE_READ_DATA,
        WriteData = FILE_WRITE_DATA,
        CreateInstance = FILE_CREATE_PIPE_INSTANCE,
        ReadAttributes = FILE_READ_ATTRIBUTES,
        WriteAttributes = FILE_WRITE_ATTRIBUTES
    };
    ENABLE_GENERIC_BITMASK_TYPE_OPS(Pipe);
    ENABLE_SIMILAR_BITMASK_TYPE_OPS(Pipe);
}
