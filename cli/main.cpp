#ifdef _WIN32

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

std::string build_json_cmd(const std::string& cmd) {
    return "{\"cmd\":\"" + cmd + "\"}";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: mars <ip> <port>\n";
        return 1;
    }

    std::string ip = argv[1];
    int port = std::stoi(argv[2]);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

    if (connect(sock, (sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) {
        std::cout << "Connection failed\n";
        return 1;
    }

    std::cout << "[MARS CLI-v2] Connected to agent.\n";

    std::string json = build_json_cmd("ping");
    send(sock, json.c_str(), json.size(), 0);

    char buffer[2048];
    int n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        std::cout << "[MARS CLI-v2] Response: " << buffer << std::endl;
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

#endif
