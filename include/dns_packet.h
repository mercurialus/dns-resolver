#pragma once

#include <cstdint>
#include <string>
#include <vector>

// DNS HEADER STRUCT (16 BITS * 6 = 12 BYTES)
#pragma pack(push, 1)
typedef struct DNSHeader
{
    // ID FOR THE DNS HEADER (16 BITS)
    uint16_t id;

    // FLAGS FOR THE DNS HEADER(16 BITS)
    // uint16_t qr;
    // uint16_t opcode;
    // uint16_t aa;
    // uint16_t tc;
    // uint16_t rd;
    // uint16_t ra;
    // uint16_t z;
    // uint16_t rcode;
    // difficult to initialize each bit everytime, so we play with bits :)
    uint16_t flags;

    // REMAINING FIELDS (16 BITS EACH)
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} DNSHeader;
#pragma pack(pop)
static_assert(sizeof(DNSHeader) == 12, "DNSHeader must be exactly 12 bytes");

// DNS QUESTION STRUCT
typedef struct DNSQuestion
{
    std::string DomainName;
    uint16_t qclass;
    uint16_t qtype;
} DNSQuestion;

typedef struct DNSResourceRecord
{
    std::string name;
    uint16_t type;
    uint16_t class_code;
    uint32_t ttl;
    uint16_t rdlength;
    std::string nsdname;

    std::vector<uint8_t> rdata;
} DNSResourceRecord;

std::vector<uint8_t> build_query_packet(const std::string &domain, uint16_t qtype);
std::vector<std::string> parse_response(const std::vector<uint8_t> &msg,
                                        uint16_t expected_qtype = 0);