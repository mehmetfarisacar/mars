#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 20847

// Basit JSON cevap oluşturucu
std::string make_json(const std::string& status, const std::string& msg) {
    return "{\"status\":\"" + status + "\",\"msg\":\"" + msg + "\"}";
}

// JSON içinden "cmd" değerini çıkar
std::string get_cmd(const std::string& json) {
    size_t pos = json.find("\"cmd\"");
    if (pos == std::string::npos) return "";

    size_t start = json.find(":", pos);
    size_t q1 = json.find("\"", start + 1);
    size_t q2 = json.find("\"", q1 + 1);

    return json.substr(q1 + 1, q2 - q1 - 1);
}

int main() {
    int server_fd, client_fd;
    sockaddr_in address{};
    socklen_t addrlen = sizeof(address);

    // Socket oluştur
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);

    std::cout << "[MARS Agent-v2][Android] Listening on port " << PORT << "...\n";

    while (true) {
        client_fd = accept(server_fd, (sockaddr*)&address, &addrlen);
        std::cout << "[MARS Agent-v2][Android] Client connected.\n";

        char buffer[2048] = {0};
        int bytes = read(client_fd, buffer, sizeof(buffer));
        if (bytes <= 0) { close(client_fd); continue; }

        std::string req(buffer);
        std::string cmd = get_cmd(req);
        std::string resp;

        if (cmd == "ping") {
            resp = make_json("ok", "pong");
        }
        else if (cmd == "echo") {
            resp = make_json("ok", "echo received");
        }
        else if (cmd == "device_info") {
            resp = "{\"status\":\"ok\",\"device\":\"Samsung Galaxy A16\",\"arch\":\"arm64\",\"android\":\"14\"}";
        }
        else if (cmd == "exit") {
            resp = make_json("ok", "bye");
            send(client_fd, resp.c_str(), resp.size(), 0);
            close(client_fd);
            break;
        }
        else {
            resp = make_json("error", "unknown command");
        }

        send(client_fd, resp.c_str(), resp.size(), 0);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
