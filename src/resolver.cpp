#include "dns_packet.h"
#include "dns_utils.h"
#include "dns_client.h"
#include "resolver.h"

#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_set>

static const std::vector<std::string> ROOT_SERVERS = {
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33"    // m.root-servers.net
};

// Helper to find glue A/AAAA records from additional section
std::string get_glue_ip(const std::vector<DNSResourceRecord> &records, const std::string &ns_name)
{
    for (const auto &rec : records)
    {
        if ((rec.type == 1 || rec.type == 28) && rec.name == ns_name)
        {
            if (rec.type == 1 && rec.rdata.size() == 4)
            {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rec.rdata.data(), ip, sizeof(ip));
                return ip;
            }
            if (rec.type == 28 && rec.rdata.size() == 16)
            {
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rec.rdata.data(), ip, sizeof(ip));
                return ip;
            }
        }
    }

    return "";
}

// Recursive resolve, {this is tough man :( }
std::vector<std::string> resolve(const std::string &domain, uint16_t record_type)
{
    std::unordered_set<std::string> visited_cnames;
    std::vector<std::string> result;

    std::vector<std::string> nameservers = ROOT_SERVERS;
    while (!nameservers.empty())
    {
        for (const auto &server_ip : nameservers)
        {
            auto query = build_query_packet(domain, record_type);
            int sockfd = send_query(query, server_ip, 53);
            if (sockfd < 0)
                continue;

            auto raw_response = recv_response(sockfd, 3);
            if (raw_response.empty())
                continue;

            auto answers = parse_response(raw_response);
            if (!answers.empty())
                return answers;

            DNSHeader header;

            std::memcpy(&header, raw_response.data(), sizeof(DNSHeader));
            size_t offset = sizeof(DNSHeader);

            std::string question_name = decode_domain(raw_response, offset); // offset is updated inside
            [[maybe_unused]] uint16_t qtype = (raw_response[offset] << 8) | raw_response[offset + 1];
            [[maybe_unused]] uint16_t qclass = (raw_response[offset + 2] << 8) | raw_response[offset + 3];
            offset += 4;

            std::vector<DNSResourceRecord> authority, additional;

            for (int i = 0; i < ntohs(header.ANCOUNT); ++i)
            {
                decode_domain(raw_response, offset);
                offset += 10; // type (2) + class (2) + ttl (4) + rdlength (2)
                uint16_t rdlength = (raw_response[offset - 2] << 8) | raw_response[offset - 1];
                offset += rdlength;
            }

            for (int i = 0; i < ntohs(header.NSCOUNT); ++i)
            {
                DNSResourceRecord rec;
                rec.name = decode_domain(raw_response, offset);
                rec.type = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                rec.class_code = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                rec.ttl = (raw_response[offset] << 24) | (raw_response[offset + 1] << 16) |
                          (raw_response[offset + 2] << 8) | raw_response[offset + 3];
                offset += 4;
                rec.rdlength = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                size_t rdata_offset = offset;
                rec.rdata = std::vector<uint8_t>(raw_response.begin() + offset,
                                                 raw_response.begin() + offset + rec.rdlength);
                offset += rec.rdlength;
                rec.name = decode_domain(raw_response, rdata_offset);
                authority.push_back(rec);
            }

            for (int i = 0; i < ntohs(header.ARCOUNT); ++i)
            {
                DNSResourceRecord rec;
                rec.name = decode_domain(raw_response, offset);
                rec.type = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                rec.class_code = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                rec.ttl = (raw_response[offset] << 24) | (raw_response[offset + 1] << 16) |
                          (raw_response[offset + 2] << 8) | raw_response[offset + 3];
                offset += 4;
                rec.rdlength = (raw_response[offset] << 8) | raw_response[offset + 1];
                offset += 2;
                rec.rdata = std::vector<uint8_t>(raw_response.begin() + offset,
                                                 raw_response.begin() + offset + rec.rdlength);
                offset += rec.rdlength;
                additional.push_back(rec);
            }
            std::vector<std::string> new_ns_ips;
            for (const auto &ns_rec : authority)
            {
                if (ns_rec.type == 2)
                { // NS record
                    std::string ns_name = ns_rec.name;
                    // std::string ns_name(reinterpret_cast<const char *>(ns_rec.rdata.data()), ns_rec.rdata.size());
                    std::string ip = get_glue_ip(additional, ns_name);
                    if (ip.empty())
                    {
                        auto resolved = resolve(ns_name, 1);
                        if (!resolved.empty())
                            ip = resolved[0];
                    }
                    if (!ip.empty())
                        new_ns_ips.push_back(ip);
                }
            }
            if (!new_ns_ips.empty())
            {
                nameservers = new_ns_ips;
                break;
            }
        }
    }
    return result;
}
