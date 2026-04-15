#ifdef _WIN32

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

#define PORT 20847

std::string make_json(const std::string& status, const std::string& msg) {
    return "{\"status\":\"" + status + "\",\"msg\":\"" + msg + "\"}";
}

std::string get_cmd(const std::string& json) {
    size_t pos = json.find("\"cmd\"");
    if (pos == std::string::npos) return "";

    size_t start = json.find(":", pos);
    size_t q1 = json.find("\"", start + 1);
    size_t q2 = json.find("\"", q1 + 1);

    return json.substr(q1 + 1, q2 - q1 - 1);
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (sockaddr*)&address, sizeof(address));
    listen(server_fd, SOMAXCONN);

    std::cout << "[MARS Agent-v2][Windows] Listening on port " << PORT << "...\n";

    while (true) {
        sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);

        SOCKET client_fd = accept(server_fd, (sockaddr*)&client_addr, &addr_len);
        std::cout << "[MARS Agent-v2][Windows] Client connected.\n";

        char buffer[2048] = {0};
        int bytes = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes <= 0) { closesocket(client_fd); continue; }

        std::string req(buffer);
        std::string cmd = get_cmd(req);
        std::string resp;

        if (cmd == "ping") resp = make_json("ok", "pong");
        else if (cmd == "echo") resp = make_json("ok", "echo received");
        else if (cmd == "device_info") resp = "{\"status\":\"ok\",\"device\":\"Windows PC\",\"arch\":\"x64\"}";
        else if (cmd == "exit") {
            resp = make_json("ok", "bye");
            send(client_fd, resp.c_str(), resp.size(), 0);
            closesocket(client_fd);
            break;
        }
        else resp = make_json("error", "unknown command");

        send(client_fd, resp.c_str(), resp.size(), 0);
        closesocket(client_fd);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}

#endif
