#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include "dns_utils.h"
#include "dns_client.h"
#include "dns_packet.h"
#include "resolver.h"
#include "lru_ttl_cache.h"

static void print_usage(const char *prog_name)
{
    std::cout << "Usage:\n"
              << "  " << prog_name << " <domain> [--type=A|AAAA|MX|CNAME] [--trace] [--show-ttl] [--bench=N]\n"
              << "Examples:\n"
              << "  " << prog_name << " example.com\n"
              << "  " << prog_name << " example.com --type=AAAA --trace\n"
              << "  " << prog_name << " example.com --bench=100\n";
}

static uint16_t qtype_string_to_code(const std::string &qtype_str)
{
    if (qtype_str == "A")
        return 1;
    if (qtype_str == "AAAA")
        return 28;
    if (qtype_str == "MX")
        return 15;
    if (qtype_str == "CNAME")
        return 5;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 5)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::string domain = argv[1];
    std::string qtype_str = "A";
    uint16_t qtype_code = 1;

    bool trace = false;
    bool show_ttl_only = false;
    int bench_n = 1;

    for (int i = 2; i < argc; ++i)
    {
        if (std::strncmp(argv[i], "--type=", 7) == 0)
        {
            qtype_str = std::string(argv[i] + 7);
            qtype_code = qtype_string_to_code(qtype_str);
            if (qtype_code == 0)
            {
                std::cerr << "Error: Unsupported record type \"" << qtype_str << "\".\n";
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        else if (std::strcmp(argv[i], "--trace") == 0)
        {
            trace = true;
        }
        else if (std::strcmp(argv[i], "--show-ttl") == 0)
        {
            show_ttl_only = true;
        }
        else if (std::strncmp(argv[i], "--bench=", 8) == 0)
        {
            bench_n = std::max(1, std::atoi(argv[i] + 8));
        }
        else
        {
            std::cerr << "Error: Unrecognized option \"" << argv[i] << "\".\n";
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // TTL-aware LRU cache for (domain|qtype) -> answers
    static LruTtlCache<std::string, std::vector<std::string>> dns_cache(512);

    const std::string cache_key = domain + "|" + std::to_string(qtype_code);

    try
    {
        if (show_ttl_only)
        {
            std::vector<std::string> dummy;
            uint32_t ttl_left = 0;
            if (dns_cache.get(cache_key, dummy, ttl_left))
            {
                std::cout << "Cache TTL remaining for " << domain
                          << " (type=" << qtype_str << "): " << ttl_left << "s\n";
            }
            else
            {
                std::cout << "No unexpired cache entry for " << domain
                          << " (type=" << qtype_str << ").\n";
            }
            return EXIT_SUCCESS;
        }

        using Clock = std::chrono::high_resolution_clock;
        auto bench_start = Clock::now();

        for (int run = 1; run <= bench_n; ++run)
        {
            std::vector<std::string> answers;
            uint32_t ttl_left = 0;

            auto start_time = Clock::now();
            bool hit = dns_cache.get(cache_key, answers, ttl_left);
            if (!hit)
            {
                // network resolve with TTL
                DnsResult res = resolve_with_ttl(domain, qtype_code);

                // TTL policy: min TTL across the RRset (and CNAME chain)
                uint32_t ttl_to_cache = res.min_ttl;
                if (res.nxdomain)
                    ttl_to_cache = std::max<uint32_t>(ttl_to_cache, 60);

                answers = std::move(res.answers);
                if (!answers.empty() || res.nxdomain)
                {
                    dns_cache.put(cache_key, answers, ttl_to_cache == 0 ? 60 : ttl_to_cache);
                    ttl_left = ttl_to_cache;
                }

                if (trace)
                {
                    std::cout << "[MISS] " << domain
                              << " type=" << qtype_str
                              << " cached_ttl=" << ttl_to_cache << "s\n";
                }
            }
            else if (trace)
            {
                std::cout << "[HIT ] " << domain
                          << " type=" << qtype_str
                          << " ttl_left=" << ttl_left << "s\n";
            }

            auto end_time = Clock::now();
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

            if (bench_n == 1)
            {
                if (answers.empty())
                {
                    std::cout << "No records found for " << domain
                              << " (type=" << qtype_str << ").\n";
                }
                else
                {
                    std::cout << "Resolved " << domain << " (type=" << qtype_str
                              << ") in " << duration_ms << " ms:\n";
                    for (const auto &a : answers)
                        std::cout << "  - " << a << "\n";
                    if (trace)
                        std::cout << "TTL remaining (approx): " << ttl_left << "s\n";
                }
            }
            else if (trace)
            {
                std::cout << "[run " << run << "/" << bench_n << "] " << duration_ms << " ms\n";
            }
        }

        auto bench_end = Clock::now();
        if (bench_n > 1)
        {
            auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(bench_end - bench_start).count();
            std::cout << "Benchmark: " << bench_n << " runs in " << total_ms << " ms\n";
            std::cout << "Cache stats: hits=" << dns_cache.hits()
                      << " misses=" << dns_cache.misses() << "\n";
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Resolution error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
