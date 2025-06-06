#include "include/dns_utils.h"
#include <random>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <cstring>

constexpr uint16_t PACKET_ID_MASK = 0xFFFF;
constexpr uint8_t DNS_LABEL_POINTER_MASK = 0xC0;

std::vector<uint8_t> encode_domain(const std::string &domain)
{
    std::vector<uint8_t> result;
    size_t start = 0, end;
    while ((end = domain.find('.', start)) != std::string::npos)
    {
        size_t len = end - start;
        result.push_back(len);
        result.insert(result.end(), domain.begin() + start, domain.begin() + end);
        start = end + 1;
    }

    size_t len = domain.size() - start;
    result.push_back(len);
    result.insert(result.end(), domain.begin() + start, domain.end());
    result.push_back(0);
    return result;
}

std::string decode_domain(const std::vector<uint8_t> &data, size_t &offset)
{
    std::string result;
    size_t orig_offset = offset;
    bool jumped = false;
    while (data[offset] != 0)
    {
        if ((data[offset] & DNS_LABEL_POINTER_MASK) == DNS_LABEL_POINTER_MASK)
        {
            if (!jumped)
                orig_offset = offset + 2;

            uint16_t pointer = ((data[offset] & 0x3F) << 8) | data[offset + 1];
            offset = pointer;
            jumped = true;
        }
        else
        {
            uint8_t len = data[offset++];
            result.append(data.begin() + offset, data.begin() + offset + len);
            offset += len;
            result.push_back('.');
        }
    }
    if (!jumped)
        offset++;
    if (!result.empty() && result.back() == '.')
        result.pop_back();
    if (jumped)
        offset = orig_offset;

    return result;
}