#include <cstdint>
#include <vector>
#include <string>

std::vector<uint8_t> encode_domain(const std::string &domain);
std::string decode_domain(const std::vector<uint8_t> &data, size_t &offset);