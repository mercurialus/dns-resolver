#pragma once

#include <cstdint>
#include <vector>
#include <string>

std::vector<uint8_t> encode_domain(const std::string &domain);
std::string decode_domain(const std::vector<uint8_t> &data, size_t &offset);

void log_info(const std::string &message);
void log_error(const std::string &message);
void dump_packet(const std::vector<uint8_t> &data);
