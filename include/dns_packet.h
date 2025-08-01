#pragma once
#include <cstdint>
#include <string>
#include <vector>

// DNS header (network byte order in the wire buffer; host order when copied)
#pragma pack(push, 1)
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};
#pragma pack(pop)

// Optional RR struct (used by some helpers)
struct DNSResourceRecord
{
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
};

uint16_t generate_transaction_id();
std::vector<uint8_t> build_query_packet(const std::string &domain, uint16_t qtype);

// Simple extractor used in the older path (returns strings only)
std::vector<std::string> parse_response(const std::vector<uint8_t> &msg,
                                        uint16_t expected_qtype /*0 = any*/);
