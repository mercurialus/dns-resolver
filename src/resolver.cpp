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
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9"};

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

// Recursive resolve, { this is tough man :( }
// Credits for Comments: ChatGPT
std::vector<std::string> resolve(const std::string &domain, uint16_t qtype)
{
    std::unordered_set<std::string> visited_cnames;
    std::vector<std::string> nameservers = ROOT_SERVERS;

    while (!nameservers.empty())
    {
        for (const std::string &ns_ip : nameservers)
        {
            /* 1. Send query ------------------------------------------------ */
            std::vector<uint8_t> query = build_query_packet(domain, qtype);
            int sockfd = send_query(query, ns_ip, 53);
            if (sockfd < 0)
                continue;

            std::vector<uint8_t> raw = recv_response(sockfd, 3);
            close(sockfd);
            if (raw.empty())
                continue;

            /* 2. Check if the answer we need is already here -------------- */
            std::vector<std::string> ans = parse_response(raw, qtype); // <-- now supports A/AAAA/CNAME/MX
            if (!ans.empty())
            {
                /* Chase CNAME transparently for A/AAAA queries */
                if ((qtype == 1 || qtype == 28) &&
                    ans.size() == 1 && !is_ip_literal(ans[0]))
                {
                    const std::string &cname_target = ans[0];
                    if (!visited_cnames.insert(cname_target).second)
                        return {};                       // CNAME loop
                    return resolve(cname_target, qtype); // recurse
                }
                return ans; // done (MX returns mail hosts, CNAME returns canonical name, etc.)
            }

            /* 3. Parse the referral (authority + additional) -------------- */
            DNSHeader hdr;
            std::memcpy(&hdr, raw.data(), sizeof(DNSHeader));
            size_t off = sizeof(DNSHeader);

            /* skip the question ------------------------------------------ */
            (void)decode_domain(raw, off); // QNAME
            off += 4;                      // QTYPE + QCLASS

            /* skip any answer RRs (we just looked) ----------------------- */
            for (int i = 0; i < ntohs(hdr.ANCOUNT); ++i)
                skip_rr(raw, off);

            /* ---- collect NS records from the authority section --------- */
            struct NSInfo
            {
                std::string nsdname;
            };
            std::vector<NSInfo> authority;

            for (int i = 0; i < ntohs(hdr.NSCOUNT); ++i)
            {
                size_t owner_off = off;
                decode_domain(raw, off); // OWNER
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 /*class*/ + 4 /*ttl*/;
                uint16_t rdlen = read16(raw, off);
                off += 2;
                size_t rdata_off = off;

                if (type == 2) // NS
                {
                    NSInfo info;
                    info.nsdname = decode_domain(raw, rdata_off);
                    authority.push_back(std::move(info));
                }
                off += rdlen;
            }

            /* ---- build glue cache from additional section -------------- */
            std::unordered_map<std::string, std::string> glue;
            for (int i = 0; i < ntohs(hdr.ARCOUNT); ++i)
            {
                std::string rrname = decode_domain(raw, off);
                uint16_t type = read16(raw, off);
                off += 2;
                off += 2 /*class*/ + 4 /*ttl*/;
                uint16_t rdlen = read16(raw, off);
                off += 2;

                if ((type == 1 || type == 28) && // A or AAAA
                    rdlen == (type == 1 ? 4 : 16))
                {
                    char ipbuf[INET6_ADDRSTRLEN];
                    inet_ntop(type == 1 ? AF_INET : AF_INET6,
                              raw.data() + off,
                              ipbuf,
                              sizeof(ipbuf));
                    glue[rrname] = ipbuf;
                }
                off += rdlen;
            }

            /* 4. Pick next name-server IPs -------------------------------- */
            std::vector<std::string> next_hop;
            for (const NSInfo &ns : authority)
            {
                std::string ip;

                /* prefer glue */
                auto it = glue.find(ns.nsdname);
                if (it != glue.end())
                {
                    ip = it->second;
                }
                else // otherwise resolve NS name
                {
                    auto ips = resolve(ns.nsdname, 1); // recurse for A
                    if (!ips.empty())
                        ip = ips.front();
                }

                if (!ip.empty())
                    next_hop.push_back(std::move(ip));
            }

            if (!next_hop.empty())
            {
                nameservers.swap(next_hop); // follow referral
                break;                      // restart with new NS list
            }
        }
    }

    return {}; // resolution failed
}
