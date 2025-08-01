#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct DnsResult
{
    std::vector<std::string> answers;
    uint32_t min_ttl = 0;
    bool nxdomain = false;
};

// Legacy API (strings only)
std::vector<std::string> resolve(const std::string &domain, uint16_t qtype);

// TTL-aware API used by the cached CLI
DnsResult resolve_with_ttl(const std::string &domain, uint16_t qtype);
