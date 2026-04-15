#include "command.h"
#include <unistd.h>
#include <sys/socket.h>
#include <string>
#include <mutex>
#include <queue>

// aktif client socket
static int g_active_client_fd = -1;
static std::mutex g_sock_mutex;

// log queue - agent_android_v3.cpp'de tanýmlý
extern std::queue<std::string> g_log_queue;
extern std::mutex g_log_mutex;

static std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"':  o += "\\\""; break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if ((unsigned char)c >= 0x20)
                o += c;
        }
    }
    return o;
}

void set_active_client(int fd) {
    std::lock_guard<std::mutex> lock(g_sock_mutex);
    g_active_client_fd = fd;
}

void send_async(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_queue.push(msg);
    fprintf(stderr, "[MARS] %s\n", msg.c_str());
    fflush(stderr);
}