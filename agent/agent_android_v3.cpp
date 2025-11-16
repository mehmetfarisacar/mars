#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "commands/command.h"
#include "utils/json.h"

#define PORT 20847

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cout << "[MARS Agent-v3][Android] Socket creation failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) {
        std::cout << "[MARS Agent-v3][Android] Bind failed\n";
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        std::cout << "[MARS Agent-v3][Android] Listen failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "[MARS Agent-v3][Android] Listening on port " << PORT << "...\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            std::cout << "[MARS Agent-v3][Android] Accept failed\n";
            continue;
        }

        std::cout << "[MARS Agent-v3][Android] Client connected.\n";

        char buffer[4096];
        int bytes = read(client_fd, buffer, sizeof(buffer) - 1);

        if (bytes <= 0) {
            close(client_fd);
            continue;
        }

        buffer[bytes] = '\0';
        std::string req(buffer);

        // ---- JSON parse ----
        std::string cmd = json_get(req, "cmd");
        std::string data = json_get(req, "data");

        std::string response = "";

        // ---- Command Routing ----
        if (cmd == "ping")                  response = cmd_ping();
        else if (cmd == "echo")             response = cmd_echo(data);
        else if (cmd == "device_info")      response = cmd_device_info();
        else if (cmd == "shell")            response = cmd_shell(data);
        else if (cmd == "read_file")        response = cmd_read_file(data);

        else if (cmd == "write_file") {
            size_t sep = data.find("|");
            if (sep != std::string::npos)
                response = cmd_write_file(data.substr(0, sep), data.substr(sep + 1));
            else
                response = json_resp("error", "invalid write_file format");
        }

        else if (cmd == "ps")               response = cmd_ps();
        else if (cmd == "list_packages")    response = cmd_list_packages();
        else if (cmd == "kill")             response = cmd_kill(data);
        else if (cmd == "get_maps")         response = cmd_get_maps(data);
        else if (cmd == "get_sysinfo")      response = cmd_get_sysinfo();

        else
            response = json_resp("error", "unknown command");

        // ---- Send Response ----
        send(client_fd, response.c_str(), response.size(), 0);

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
