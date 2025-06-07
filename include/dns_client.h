#pragma once

#include <cstdint>
#include <vector>
#include <string>

int send_query(std::vector<uint8_t> &packet, const std::string &server_ip, uint16_t port);
std::vector<uint8_t> recv_response(int sockfd, int timeout);