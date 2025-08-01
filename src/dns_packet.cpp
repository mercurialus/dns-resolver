#include "dns_packet.h"
#include "dns_utils.h"
#include <random>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <cstring>

uint16_t generate_transaction_id()
{
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xFFFF);
    return dist(rng);
}

std::vector<uint8_t> build_query_packet(const std::string &domain, uint16_t qtype)
{
    std::vector<uint8_t> packet;

    DNSHeader hdr{};
    hdr.id = htons(generate_transaction_id());
    hdr.flags = htons(0x0100); // RD=1
    hdr.QDCOUNT = htons(1);

    packet.insert(packet.end(),
                  reinterpret_cast<uint8_t *>(&hdr),
                  reinterpret_cast<uint8_t *>(&hdr) + sizeof(DNSHeader));

    std::vector<uint8_t> qname = encode_domain(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());

    uint16_t qtype_net = htons(qtype);
    uint16_t qclass_net = htons(1); // IN

    packet.insert(packet.end(),
                  reinterpret_cast<uint8_t *>(&qtype_net),
                  reinterpret_cast<uint8_t *>(&qtype_net) + 2);
    packet.insert(packet.end(),
                  reinterpret_cast<uint8_t *>(&qclass_net),
                  reinterpret_cast<uint8_t *>(&qclass_net) + 2);

    return packet;
}

std::vector<std::string>
parse_response(const std::vector<uint8_t> &msg, uint16_t expected_qtype)
{
    std::vector<std::string> out;
    if (msg.size() < sizeof(DNSHeader))
        return out;

    DNSHeader hdr;
    std::memcpy(&hdr, msg.data(), sizeof(DNSHeader));

    size_t off = sizeof(DNSHeader);
    uint16_t qd = ntohs(hdr.QDCOUNT);
    uint16_t an = ntohs(hdr.ANCOUNT);

    for (int i = 0; i < qd; ++i)
    {
        decode_domain(msg, off); // QNAME
        off += 4;                // QTYPE + QCLASS
    }

    for (int i = 0; i < an; ++i)
    {
        decode_domain(msg, off); // OWNER

        if (off + 10 > msg.size())
            return out;

        uint16_t type = read_u16(msg, off);
        off += 2;
        (void)read_u16(msg, off);
        off += 2; // class
        (void)read_u32(msg, off);
        off += 4; // ttl
        uint16_t rdlen = read_u16(msg, off);
        off += 2;

        if (off + rdlen > msg.size())
            return out;

        bool wanted = (expected_qtype == 0 ||
                       expected_qtype == type ||
                       ((expected_qtype == 1 || expected_qtype == 28) &&
                        (type == 1 || type == 28)));

        if (wanted)
        {
            switch (type)
            {
            case 1: // A
                if (rdlen == 4)
                {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, msg.data() + off, ip, sizeof(ip));
                    out.emplace_back(ip);
                }
                break;
            case 28: // AAAA
                if (rdlen == 16)
                {
                    char ip6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, msg.data() + off, ip6, sizeof(ip6));
                    out.emplace_back(ip6);
                }
                break;
            case 5: // CNAME
            {
                size_t cname_off = off;
                out.emplace_back(decode_domain(msg, cname_off));
                break;
            }
            case 15: // MX
            {
                if (rdlen >= 3)
                {
                    size_t rdoff = off + 2; // skip preference
                    out.emplace_back(decode_domain(msg, rdoff));
                }
                break;
            }
            default:
                break;
            }
        }
        off += rdlen;
    }

    return out;
}
