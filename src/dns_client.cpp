#include "dns_client.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

constexpr size_t MAX_DNS_RESPONSE = 512;

int send_query(std::vector<uint8_t> &packet, const std::string &server_ip, uint16_t port)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        std::cerr << "Socket creation failed.\n";
        std::cout << std::endl;
        return -1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << " Invalid server IP address.\n";
        close(sockfd);
        return -1;
    }

    ssize_t sent = sendto(sockfd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));

    if (sent < 0)
    {
        std::cerr << "Failed to send DNS query.\n";
        close(sockfd);
        return -1;
    }

    return sockfd;
}

std::vector<uint8_t> recv_response(int sockfd, int timeout_secs)
{
    std::vector<uint8_t> response(MAX_DNS_RESPONSE);

    timeval tv{};
    tv.tv_sec = timeout_secs;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        std::cerr << "Failed to set socket timeout.\n";
        close(sockfd);
        return {};
    }

    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    ssize_t received = recvfrom(sockfd, response.data(), response.size(), 0,
                                reinterpret_cast<sockaddr *>(&from_addr), &from_len);

    close(sockfd);

    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            std::cerr << "TIMEOUT: No response received.\n";
        }
        else
        {
            std::cerr << "Error receiving DNS response.\n";
        }
        return {};
    }

    response.resize(received);
    return response;
}
