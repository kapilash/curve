#pragma once
#include <stdint.h>
namespace curve_bstr
{
    struct ByteString
    {
        uint32_t length {0};
        uint32_t metdata {0};
        uint8_t* data {nullptr};
    public:
        inline explicit ByteString() noexcept : length{ 0 }, metdata{ 0 }, data{ 0 } {}
        inline explicit ByteString(const ByteString& other) noexcept
            : length{ other.length }
            , metdata{ other.metdata }
            , data{nullptr} 
        {
            if (other.length > 0) 
            {
                data = new uint8_t[other.length];
                std::memcpy(data, other.data, other.length);
            }
        }

        inline explicit ByteString(ByteString&& other) noexcept
            : length{ std::move(other.length) }
            , metdata{ std::move(other.metdata) }
        {
            data = other.data;
            other.data = nullptr;
            other.length = 0;
            other.metdata = 0;
        }

        inline ByteString& operator=(const ByteString& other) noexcept 
        {
            if (other.length > this->length)
            {
                if(data != nullptr)
                    delete[] data;
                data = new uint8_t[other.length];
                
            }
            std::memcpy(data, other.data, other.length);
            length = other.length;
            metdata = other.metdata;
            return *this;
        }

        inline ByteString& operator=(ByteString&& other) noexcept
        {
            if (data != nullptr)
                delete data;
            length = std::move(other.length);
            metdata = std::move(other.metdata);
            data = other.data;
            other.data = nullptr;
            other.length = 0;
            other.metdata = 0;
        }

        ~ByteString() noexcept
        {
            if (data != nullptr)
                delete[]data;
            length = 0;
            metdata = 0;
        }

        inline uint8_t readU8At(uint32_t pos) const
        {
            return data[pos];
        }

        inline uint16_t readU16At(uint32_t pos) const
        {
            uint16_t value;
            std::memcpy(&value, data + pos, 2);
            return value;
        }
    };
}
