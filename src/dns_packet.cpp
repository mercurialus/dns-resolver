#include "include/dns_packet.h"
#include <random>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <cstring>

constexpr uint16_t PACKET_ID_MASK = 0xFFFF;
constexpr uint8_t DNS_LABEL_POINTER_MASK = 0xC0;

uint16_t generate_transaction_id()
{
    // for random number generator i am using mersenne twister
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xFFFF); // 0xFFFF=65535 == 2^16-1
    return dist(rng);
}
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
std::vector<uint8_t> build_query_packet(const std::string &domain, uint16_t qtype)
{
    std::vector<uint8_t> packet;

    DNSHeader header{};
    header.id = htons(generate_transaction_id());
    header.flags = htons(0x0100); // rd = 1
    header.QDCOUNT = htons(1);
    header.ANCOUNT = 0;
    header.NSCOUNT = 0;
    header.ARCOUNT = 0;

    packet.insert(packet.end(), reinterpret_cast<uint8_t *>(&header), reinterpret_cast<uint8_t *>(&header) + sizeof(DNSHeader));
    std::vector<uint8_t> qname = encode_domain(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());

    uint16_t qtype_net = htons(qtype);
    uint16_t qclass_net = htons(1);

    packet.insert(packet.end(), reinterpret_cast<uint8_t *>(&qtype_net), reinterpret_cast<uint8_t *>(&qtype_net) + 2);
    packet.insert(packet.end(), reinterpret_cast<uint8_t *>(&qclass_net), reinterpret_cast<uint8_t *>(&qclass_net) + 2);

    return packet;
}

std::vector<std::string> parse_response(const std::vector<uint8_t> &data)
{
    std::vector<std::string> parsed;

    if (data.size() < sizeof(DNSHeader))
        return parsed;

    DNSHeader header;

    std::memcpy(&header, data.data(), sizeof(DNSHeader));

    uint16_t qdcount = ntohs(header.QDCOUNT);
    uint16_t ancount = ntohs(header.ANCOUNT);

    size_t offset = sizeof(DNSHeader);

    for (int i = 0; i < qdcount; ++i)
    {
        decode_domain(data, offset);
        offset += 4; // QTYPE (2) + QCLASS (2)
    }

    for (int i = 0; i < ancount; ++i)
    {
        std::string name = decode_domain(data, offset);

        if (offset + 10 > data.size())
            break;

        uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(&data[offset]));
        uint16_t class_code = ntohs(*reinterpret_cast<const uint16_t *>(&data[offset + 2]));
        uint16_t ttl = ntohs(*reinterpret_cast<const uint16_t *>(&data[offset + 4]));
        uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(&data[offset + 8]));

        offset += 10;
        if (offset + rdlength > data.size())
            break;

        if (type == 1 && rdlength == 4)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &data[offset], ip, sizeof(ip));
            parsed.emplace_back(ip);
        }
        else if (type == 5)
        {
            size_t cname_offset = offset;
            std::string cname = decode_domain(data, cname_offset);
            parsed.push_back(cname);
        }

        offset += rdlength;
    }

    return parsed;
}