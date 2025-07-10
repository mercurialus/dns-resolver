#pragma once

#include <cstdint>
#include <vector>
#include <string>

std::vector<uint8_t> encode_domain(const std::string &domain);
std::string decode_domain(const std::vector<uint8_t> &data, size_t &offset);

void log_info(const std::string &message);
void log_error(const std::string &message);
void dump_packet(const std::vector<uint8_t> &data);
uint16_t read16(const std::vector<uint8_t> &buf, size_t pos);
bool is_ip_literal(const std::string &s);
void skip_rr(const std::vector<uint8_t> &buf, size_t &off);
uint16_t read_u16(const std::vector<uint8_t> &buf, size_t pos);
uint32_t read_u32(const std::vector<uint8_t> &buf, size_t pos);