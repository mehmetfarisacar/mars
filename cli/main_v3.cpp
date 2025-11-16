#ifdef _WIN32

#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// ---- JSON builder ----
std::string json_cmd(const std::string& cmd, const std::string& data = "") {
    if (data.empty())
        return "{\"cmd\":\"" + cmd + "\"}";
    return "{\"cmd\":\"" + cmd + "\",\"data\":\"" + data + "\"}";
}

// ---- HELP ----
void show_help() {
    std::cout <<
        "MARS CLI v3.0\n"
        "Usage:\n"
        "  mars-cli-v3 <ip> <port> <command> [args]\n\n"
        "Commands:\n"
        "  ping                        Test connectivity\n"
        "  echo <text>                 Return the same text\n"
        "  device_info                 Show device model/arch/version\n"
        "  shell <cmd>                 Run shell command on device\n"
        "  read_file <path>            Read file contents\n"
        "  write_file <path> <data>    Write to a file\n"
        "  ps                          List processes\n"
        "  list_packages               List installed packages\n"
        "  kill <pid>                  Kill process\n"
        "  get_maps <pid>              Read /proc/<pid>/maps\n"
        "  get_sysinfo                 Kernel, CPU, RAM info\n"
        "  --help                      Show this help\n\n"
        "Examples:\n"
        "  mars-cli-v3 127.0.0.1 20847 ping\n"
        "  mars-cli-v3 127.0.0.1 20847 echo \"hello\"\n"
        "  mars-cli-v3 127.0.0.1 20847 shell \"id\"\n"
        "  mars-cli-v3 127.0.0.1 20847 read_file /proc/self/maps\n"
        "  mars-cli-v3 127.0.0.1 20847 write_file /sdcard/t.txt \"test\"\n"
        "  mars-cli-v3 127.0.0.1 20847 ps\n"
        "  mars-cli-v3 127.0.0.1 20847 list_packages\n"
        "  mars-cli-v3 127.0.0.1 20847 get_sysinfo\n";
}

// ---- MAIN ----
int main(int argc, char* argv[]) {

    if (argc < 4) {
        show_help();
        return 0;
    }

    if (std::string(argv[1]) == "--help") {
        show_help();
        return 0;
    }

    std::string ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string cmd = argv[3];

    // ---- Argüman birleþtirme ----
    std::string data = "";
    for (int i = 4; i < argc; i++) {
        data += argv[i];
        if (i + 1 < argc) data += " ";
    }

    // write_file özel format: path|content
    if (cmd == "write_file") {
        if (argc < 6) {
            std::cout << "write_file requires: <path> <data>\n";
            return 0;
        }

        std::string path = argv[4];
        std::string text = "";

        for (int i = 5; i < argc; i++) {
            text += argv[i];
            if (i + 1 < argc) text += " ";
        }

        data = path + "|" + text;
    }

    // ---- Winsock init ----
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

    if (connect(sock, (sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) {
        std::cerr << "Connection failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // ---- JSON gönder ----
    std::string json = json_cmd(cmd, data);
    send(sock, json.c_str(), json.size(), 0);

    // ---- cevap al ----
    char buffer[8192];
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);

    if (n > 0) {
        buffer[n] = '\0';
        std::cout << buffer << "\n";
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

#endif
