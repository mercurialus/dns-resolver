#include "include/dns_packet.h"
#include "include/dns_utils.h"
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