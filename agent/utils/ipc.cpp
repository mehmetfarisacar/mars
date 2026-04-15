#include "ipc.h"
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <errno.h>
#include <mutex>

// ─── Abstract socket helper ───
static socklen_t fill_addr(sockaddr_un& addr, const std::string& name) {
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name.c_str(), sizeof(addr.sun_path) - 2);
    return (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name.size());
}

static int make_server(const std::string& name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un addr{};
    socklen_t len = fill_addr(addr, name);
    if (bind(fd, (sockaddr*)&addr, len) < 0) { close(fd); return -1; }
    listen(fd, 2);
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

static int accept_one(int server_fd, int timeout_ms) {
    if (server_fd < 0) return -1;
    pollfd pfd{ server_fd, POLLIN, 0 };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    return accept(server_fd, nullptr, nullptr);
}

static bool send_msg(int fd, const IPCMsg& msg) {
    if (fd < 0) return false;
    return write(fd, &msg, sizeof(msg)) == sizeof(msg);
}

static bool recv_msg(int fd, IPCMsg& msg, int timeout_ms) {
    if (fd < 0) return false;
    pollfd pfd{ fd, POLLIN, 0 };
    if (poll(&pfd, 1, timeout_ms) <= 0) return false;
    return read(fd, &msg, sizeof(msg)) == (int)sizeof(msg);
}

// ═══════════════════════════════════════════════════════
//  AGENT (SERVER) — iki ayrı server socket
//  cmd_server:  hook komutları (agent → SO)
//  cb_server:   callback mesajları (SO → agent)
// ═══════════════════════════════════════════════════════
static int g_cmd_server = -1;
static int g_cb_server = -1;
static int g_cmd_client = -1;  // SO'nun cmd bağlantısı
static int g_cb_client = -1;  // SO'nun cb bağlantısı
static std::mutex g_cmd_mutex;
static std::mutex g_cb_mutex;

bool ipc_server_start(const std::string& cmd_path,
    const std::string& cb_path) {
    g_cmd_server = make_server(cmd_path);
    g_cb_server = make_server(cb_path);
    return g_cmd_server >= 0 && g_cb_server >= 0;
}

void ipc_server_stop() {
    if (g_cmd_client >= 0) { close(g_cmd_client); g_cmd_client = -1; }
    if (g_cb_client >= 0) { close(g_cb_client);  g_cb_client = -1; }
    if (g_cmd_server >= 0) { close(g_cmd_server);  g_cmd_server = -1; }
    if (g_cb_server >= 0) { close(g_cb_server);   g_cb_server = -1; }
}

static void ensure_cmd_client() {
    std::lock_guard<std::mutex> lock(g_cmd_mutex);
    int fd = accept_one(g_cmd_server, 0);
    if (fd >= 0) {
        if (g_cmd_client >= 0) close(g_cmd_client);
        g_cmd_client = fd;
    }
}

static void ensure_cb_client() {
    std::lock_guard<std::mutex> lock(g_cb_mutex);
    int fd = accept_one(g_cb_server, 0);
    if (fd >= 0) {
        if (g_cb_client >= 0) close(g_cb_client);
        g_cb_client = fd;
    }
}

bool ipc_cmd_send(const IPCMsg& msg) {
    ensure_cmd_client();
    std::lock_guard<std::mutex> lock(g_cmd_mutex);
    if (g_cmd_client < 0) {
        // Bağlantı bekle
        lock.~lock_guard();
        int fd = accept_one(g_cmd_server, 3000);
        if (fd < 0) return false;
        std::lock_guard<std::mutex> lock2(g_cmd_mutex);
        if (g_cmd_client >= 0) close(g_cmd_client);
        g_cmd_client = fd;
        return send_msg(g_cmd_client, msg);
    }
    return send_msg(g_cmd_client, msg);
}

bool ipc_cmd_recv(IPCMsg& msg, int timeout_ms) {
    ensure_cmd_client();
    std::lock_guard<std::mutex> lock(g_cmd_mutex);
    return recv_msg(g_cmd_client, msg, timeout_ms);
}

bool ipc_cb_recv(IPCMsg& msg, int timeout_ms) {
    ensure_cb_client();
    // CB bağlantısı yoksa bekle
    {
        std::lock_guard<std::mutex> lock(g_cb_mutex);
        if (g_cb_client < 0) {
            lock.~lock_guard();
            int fd = accept_one(g_cb_server, timeout_ms);
            if (fd < 0) return false;
            std::lock_guard<std::mutex> lock2(g_cb_mutex);
            g_cb_client = fd;
        }
    }
    std::lock_guard<std::mutex> lock(g_cb_mutex);
    return recv_msg(g_cb_client, msg, timeout_ms);
}

bool ipc_cb_send(const IPCMsg& msg) {
    std::lock_guard<std::mutex> lock(g_cb_mutex);
    return send_msg(g_cb_client, msg);
}

// ═══════════════════════════════════════════════════════
//  SO (CLIENT) — iki ayrı client socket
// ═══════════════════════════════════════════════════════
static int g_cmd_sock = -1;
static int g_cb_sock = -1;

static int connect_to(const std::string& name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un addr{};
    socklen_t len = fill_addr(addr, name);
    for (int i = 0; i < 20; i++) {
        if (connect(fd, (sockaddr*)&addr, len) == 0) return fd;
        usleep(100000);
    }
    close(fd);
    return -1;
}

bool ipc_client_connect(const std::string& cmd_path,
    const std::string& cb_path) {
    g_cmd_sock = connect_to(cmd_path);
    if (g_cmd_sock < 0) return false;
    g_cb_sock = connect_to(cb_path);
    if (g_cb_sock < 0) { close(g_cmd_sock); g_cmd_sock = -1; return false; }
    return true;
}

void ipc_client_disconnect() {
    if (g_cmd_sock >= 0) { close(g_cmd_sock); g_cmd_sock = -1; }
    if (g_cb_sock >= 0) { close(g_cb_sock);  g_cb_sock = -1; }
}

bool ipc_client_cmd_recv(IPCMsg& msg, int timeout_ms) {
    return recv_msg(g_cmd_sock, msg, timeout_ms);
}

bool ipc_client_cmd_send(const IPCMsg& msg) {
    return send_msg(g_cmd_sock, msg);
}

bool ipc_client_cb_send(const IPCMsg& msg) {
    return send_msg(g_cb_sock, msg);
}

bool ipc_client_cb_recv(IPCMsg& msg, int timeout_ms) {
    return recv_msg(g_cb_sock, msg, timeout_ms);
}
