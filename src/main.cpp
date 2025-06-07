#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include "dns_utils.h"
#include "dns_client.h"
#include "dns_packet.h"
#include "resolver.h"

static void print_usage(const char *prog_name)
{
    std::cout << "Usage:\n"
              << "  " << prog_name << " <domain> [--type=A|AAAA|MX|CNAME]\n"
              << "Examples:\n"
              << "  " << prog_name << " example.com\n"
              << "  " << prog_name << " example.com --type=AAAA\n";
}

// Convert a string QTYPE ("A", "AAAA", "MX", "CNAME") into its numeric DNS type code.
// Returns 0 on error.
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
    if (argc < 2 || argc > 3)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::string domain = argv[1];
    std::string qtype_str = "A"; // Default record type
    uint16_t qtype_code = 1;     // Numeric code for "A"

    if (argc == 3)
    {
        if (std::strncmp(argv[2], "--type=", 7) == 0)
        {
            qtype_str = std::string(argv[2] + 7);
            qtype_code = qtype_string_to_code(qtype_str);
            if (qtype_code == 0)
            {
                std::cerr << "Error: Unsupported record type \"" << qtype_str << "\".\n";
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        else
        {
            std::cerr << "Error: Unrecognized option \"" << argv[2] << "\".\n";
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    try
    {
        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<std::string> answers = resolve(domain, qtype_code);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        if (answers.empty())
        {
            std::cout << "No records found for " << domain << " (type=" << qtype_str << ").\n";
            return EXIT_SUCCESS;
        }

        std::cout << "Resolved " << domain << " (type=" << qtype_str << ") in "
                  << duration_ms << " ms:\n";
        for (const auto &answer : answers)
        {
            std::cout << "  - " << answer << "\n";
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Resolution error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
