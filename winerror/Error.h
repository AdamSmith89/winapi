#pragma once

#include "overloads.h"

namespace winapi::winerror
{
    class Error
    {
    public:
        explicit Error(DWORD const errorCode)
            : m_errorCode{ errorCode }
        {
        }

        DWORD Code() const { return m_errorCode; }
        template<typename char_type=char>
        std::optional<std::basic_string<char_type>> AsString() const
        {
            // FormatMessage is weird in that lpBuffer is just a LPTSTR but it should really be an LPTSTR* when
            // using FORMAT_MESSAGE_ALLOCATE_BUFFER. Pretty sure it's doing something funky under the hood.
            char_type* pTempBuffer = nullptr;
            auto pWinBuffer = reinterpret_cast<overloads<char_type>::win_type>(&pTempBuffer);

            auto const numCharsAllocated = overloads<char_type>::Format_Message()(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,    // dwFlags
                nullptr,                                    // lpSource     - location of the message definition.
                m_errorCode,                                // dwMessageId  - ignored if dwFlags includes FORMAT_MESSAGE_FROM_STRING.
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // dwLanguageId - Language identifier for the requestd message.
                pWinBuffer,                                 // lpBuffer     - Buffer that receives the null-terminated string.
                0,                                          // nSize        - Specifies size of output buffer if FORMAT_MESSAGE_ALLOCATE_BUFFER is not set.
                nullptr);                                   // Arguments    - Array of values to insert into the formatted message.

            if (numCharsAllocated > 0)
            {
                auto const message = std::basic_string<char_type>(pTempBuffer, numCharsAllocated);
                LocalFree(pTempBuffer);
                return message;
            }

            return {};
        }

        bool Succeeded() const
        {
            return SUCCEEDED(m_errorCode);
        }

        bool Failed() const
        {
            return FAILED(m_errorCode);
        }

    private:
        DWORD m_errorCode = ERROR_SUCCESS;
    };

    Error GetLastError()
    {
        return Error(::GetLastError());
    }
}