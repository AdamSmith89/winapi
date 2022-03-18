#pragma once

namespace winapi
{
    // RAII wrapper around Windows HANDLE types. Movable, not-copyable
    class Handle
    {
    public:
        explicit Handle(HANDLE rawHandle) noexcept
            : m_rawHandle{ rawHandle }
        {
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        Handle(Handle&& rhs) noexcept
        {
            m_rawHandle = rhs.m_rawHandle;
            rhs.m_rawHandle = nullptr;
        }
        Handle& operator=(Handle&& rhs) noexcept
        {
            m_rawHandle = rhs.m_rawHandle;
            rhs.m_rawHandle = nullptr;
            return *this;
        }

        ~Handle() noexcept
        {
            if (m_rawHandle != nullptr)
            {
                CloseHandle(m_rawHandle);
                m_rawHandle = nullptr;
            }
        }

        HANDLE Get() const { return m_rawHandle; }

    private:
        HANDLE m_rawHandle = nullptr;
    };
}