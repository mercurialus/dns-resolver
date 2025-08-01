#include "dns_packet.h"
#include "dns_utils.h"
#include "dns_client.h"
#include "resolver.h"

#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_set>
#include <unordered_map>
#include <unistd.h>

static const std::vector<std::string> ROOT_SERVERS = {
    "1.1.1.1", "8.8.8.8", "9.9.9.9"};

// Legacy recursive resolver (no TTL), retained for completeness.
std::vector<std::string> resolve(const std::string &domain, uint16_t qtype)
{
    std::unordered_set<std::string> visited_cnames;
    std::vector<std::string> nameservers = ROOT_SERVERS;

    while (!nameservers.empty())
    {
        for (const std::string &ns_ip : nameservers)
        {
            std::vector<uint8_t> query = build_query_packet(domain, qtype);
            int sockfd = send_query(query, ns_ip, 53);
            if (sockfd < 0)
                continue;

            std::vector<uint8_t> raw = recv_response(sockfd, 3);
            if (raw.empty())
                continue;

            std::vector<std::string> ans = parse_response(raw, qtype);
            if (!ans.empty())
            {
                if ((qtype == 1 || qtype == 28) &&
                    ans.size() == 1 && !is_ip_literal(ans[0]))
                {
                    const std::string &cname_target = ans[0];
                    if (!visited_cnames.insert(cname_target).second)
                        return {};
                    return resolve(cname_target, qtype);
                }
                return ans;
            }

            DNSHeader hdr;
            std::memcpy(&hdr, raw.data(), sizeof(DNSHeader));
            size_t off = sizeof(DNSHeader);

            // skip Q
            (void)decode_domain(raw, off);
            off += 4;

            // skip AN
            for (int i = 0; i < ntohs(hdr.ANCOUNT); ++i)
                skip_rr(raw, off);

            // authority NS names
            struct NSInfo
            {
                std::string nsdname;
            };
            std::vector<NSInfo> authority;
            for (int i = 0; i < ntohs(hdr.NSCOUNT); ++i)
            {
                decode_domain(raw, off);
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 + 4;
                uint16_t rdlen = read16(raw, off);
                off += 2;
                size_t rdata_off = off;
                if (type == 2)
                {
                    NSInfo info;
                    info.nsdname = decode_domain(raw, rdata_off);
                    authority.push_back(std::move(info));
                }
                off += rdlen;
            }

            // additional glue
            std::unordered_map<std::string, std::string> glue;
            for (int i = 0; i < ntohs(hdr.ARCOUNT); ++i)
            {
                std::string rrname = decode_domain(raw, off);
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 + 4;
                uint16_t rdlen = read16(raw, off);
                off += 2;

                if ((type == 1 || type == 28) && rdlen == (type == 1 ? 4 : 16))
                {
                    char ipbuf[INET6_ADDRSTRLEN];
                    inet_ntop(type == 1 ? AF_INET : AF_INET6,
                              raw.data() + off, ipbuf, sizeof(ipbuf));
                    glue[rrname] = ipbuf;
                }
                off += rdlen;
            }

            std::vector<std::string> next_hop;
            for (const auto &ns : authority)
            {
                std::string ip;
                auto it = glue.find(ns.nsdname);
                if (it != glue.end())
                    ip = it->second;
                else
                {
                    auto ips = resolve(ns.nsdname, 1);
                    if (!ips.empty())
                        ip = ips.front();
                }
                if (!ip.empty())
                    next_hop.push_back(std::move(ip));
            }

            if (!next_hop.empty())
            {
                nameservers.swap(next_hop);
                break;
            }
        }
    }
    return {};
}

// TTL-aware recursive resolver used by cached CLI
static DnsResult parse_answers_and_ttl(const std::vector<uint8_t> &raw,
                                       uint16_t qtype,
                                       std::vector<std::string> &out_addrs,
                                       std::string &out_cname,
                                       uint32_t &out_min_ttl)
{
    DnsResult res;
    if (raw.size() < sizeof(DNSHeader))
        return res;

    DNSHeader hdr;
    std::memcpy(&hdr, raw.data(), sizeof(DNSHeader));
    uint16_t an = ntohs(hdr.ANCOUNT);
    uint16_t qd = ntohs(hdr.QDCOUNT);

    // RCODE in low 4 bits
    uint16_t flags = ntohs(hdr.flags);
    uint16_t rcode = (flags & 0x000F);
    if (rcode == 3)
    {
        res.nxdomain = true;
        return res;
    }

    size_t off = sizeof(DNSHeader);

    // skip questions
    for (int i = 0; i < qd; ++i)
    {
        decode_domain(raw, off);
        off += 4;
    }

    uint32_t min_ttl = UINT32_MAX;
    std::string cname;
    for (int i = 0; i < an; ++i)
    {
        decode_domain(raw, off); // owner
        uint16_t type = read_u16(raw, off);
        off += 2;
        (void)read_u16(raw, off);
        off += 2; // class
        uint32_t ttl = read_u32(raw, off);
        off += 4;
        uint16_t rdlen = read_u16(raw, off);
        off += 2;

        if (type == 1 && rdlen == 4)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, raw.data() + off, ip, sizeof(ip));
            out_addrs.emplace_back(ip);
            if (ttl < min_ttl)
                min_ttl = ttl;
        }
        else if (type == 28 && rdlen == 16)
        {
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, raw.data() + off, ip6, sizeof(ip6));
            out_addrs.emplace_back(ip6);
            if (ttl < min_ttl)
                min_ttl = ttl;
        }
        else if (type == 5)
        { // CNAME
            size_t rdoff = off;
            cname = decode_domain(raw, rdoff);
            if (ttl < min_ttl)
                min_ttl = ttl;
        }
        off += rdlen;
    }

    out_cname = std::move(cname);
    if (min_ttl != UINT32_MAX)
        out_min_ttl = min_ttl;
    res.min_ttl = (min_ttl == UINT32_MAX) ? 0 : min_ttl;
    return res;
}

DnsResult resolve_with_ttl(const std::string &domain, uint16_t qtype)
{
    std::unordered_set<std::string> visited_cnames;
    std::vector<std::string> nameservers = ROOT_SERVERS;

    while (!nameservers.empty())
    {
        for (const std::string &ns_ip : nameservers)
        {
            // 1) send query
            std::vector<uint8_t> query = build_query_packet(domain, qtype);
            int sockfd = send_query(query, ns_ip, 53);
            if (sockfd < 0)
                continue;

            std::vector<uint8_t> raw = recv_response(sockfd, 3);
            if (raw.empty())
                continue;

            // 2) parse answers with TTL
            std::vector<std::string> addrs;
            std::string cname;
            uint32_t min_ttl = 0;
            DnsResult header_res = parse_answers_and_ttl(raw, qtype, addrs, cname, min_ttl);

            if (header_res.nxdomain)
            {
                // Optionally parse SOA MINIMUM for negative caching; here we return NXDOMAIN with ttl=60
                return DnsResult{{}, 60, true};
            }

            if (!addrs.empty())
            {
                return DnsResult{std::move(addrs), min_ttl, false};
            }

            // CNAME chase for A/AAAA queries
            if ((qtype == 1 || qtype == 28) && !cname.empty())
            {
                if (!visited_cnames.insert(cname).second)
                {
                    return DnsResult{{}, 0, false}; // loop
                }
                DnsResult next = resolve_with_ttl(cname, qtype);
                if (!next.answers.empty())
                {
                    // TTL for the chain = min(CNAME ttl, target ttl)
                    uint32_t chain_ttl = (min_ttl == 0) ? next.min_ttl
                                                        : (next.min_ttl == 0 ? min_ttl
                                                                             : std::min(min_ttl, next.min_ttl));
                    next.min_ttl = chain_ttl;
                    return next;
                }
            }

            // 3) referral handling (authority + additional)
            DNSHeader hdr;
            std::memcpy(&hdr, raw.data(), sizeof(DNSHeader));
            size_t off = sizeof(DNSHeader);

            // skip question(s)
            for (int i = 0; i < ntohs(hdr.QDCOUNT); ++i)
            {
                decode_domain(raw, off);
                off += 4;
            }

            // skip answer(s)
            for (int i = 0; i < ntohs(hdr.ANCOUNT); ++i)
            {
                skip_rr(raw, off);
            }

            // collect NS from authority
            struct NSInfo
            {
                std::string nsdname;
            };
            std::vector<NSInfo> authority;
            for (int i = 0; i < ntohs(hdr.NSCOUNT); ++i)
            {
                decode_domain(raw, off); // owner
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 + 4;
                uint16_t rdlen = read16(raw, off);
                off += 2;
                size_t rdata_off = off;
                if (type == 2)
                { // NS
                    NSInfo info;
                    info.nsdname = decode_domain(raw, rdata_off);
                    authority.push_back(std::move(info));
                }
                off += rdlen;
            }

            // build glue from additional
            std::unordered_map<std::string, std::string> glue;
            for (int i = 0; i < ntohs(hdr.ARCOUNT); ++i)
            {
                std::string rrname = decode_domain(raw, off);
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 + 4;
                uint16_t rdlen = read16(raw, off);
                off += 2;

                if ((type == 1 || type == 28) && rdlen == (type == 1 ? 4 : 16))
                {
                    char ipbuf[INET6_ADDRSTRLEN];
                    inet_ntop(type == 1 ? AF_INET : AF_INET6,
                              raw.data() + off, ipbuf, sizeof(ipbuf));
                    glue[rrname] = ipbuf;
                }
                off += rdlen;
            }

            std::vector<std::string> next_hop;
            for (const auto &ns : authority)
            {
                std::string ip;
                auto it = glue.find(ns.nsdname);
                if (it != glue.end())
                    ip = it->second;
                else
                {
                    // resolve nameserver name (A)
                    DnsResult ns_res = resolve_with_ttl(ns.nsdname, 1);
                    if (!ns_res.answers.empty())
                        ip = ns_res.answers.front();
                }
                if (!ip.empty())
                    next_hop.push_back(std::move(ip));
            }

            if (!next_hop.empty())
            {
                nameservers.swap(next_hop);
                break; // follow referral
            }
        }
    }

    return DnsResult{};
}
