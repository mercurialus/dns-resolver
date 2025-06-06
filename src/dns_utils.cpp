#include "include/dns_utils.h"
#include <iomanip>
#include <iostream>
#include <chrono>
#include <ctime>
#include <cctype>
#include <vector>
#include <string>

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

std::string current_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto tm_now = std::localtime(&time_t_now);

    std::ostringstream oss;

    oss << "[" << std::put_time(tm_now, "%Y-%m-%d %H:%M:%S") << "]";
    return oss.str();
}

void log_info(const std::string &message)
{
    std::cout << current_timestamp() << " INFO: " << message << std::endl;
}

void log_error(const std::string &message)
{
    std::cerr << current_timestamp() << " ERROR:" << message << std::endl;
}

void dump_packet(std::vector<uint8_t> &data)
{
    const size_t bytes_per_line = 16;

    for (size_t i = 0; i < data.size(); i += bytes_per_line)
    {
        std::cout << std::setw(4) << std::setfill('0') << std::hex << i << ": ";

        for (size_t j = 0; j < bytes_per_line; ++j)
        {
            if (i + j < data.size())
            {
                std::cout << std::setw(2) << static_cast<int>(data[i + j]) << " ";
            }
            else
            {
                std::cout << " ";
            }
        }
        std::cout << " ";
        for (size_t j = 0; j < bytes_per_line && i + j < data.size(); ++j)
        {
            char c = static_cast<char>(data[i + j]);
            std::cout << (std::isprint(static_cast<unsigned char>(c)) ? c : '.');
        }
        std::cout << std::endl;
    }
}
