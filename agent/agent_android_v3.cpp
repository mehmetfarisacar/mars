#include <iostream>
#include <string>
#include <thread>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "commands/command.h"
#include "utils/json.h"
#include "utils/js_runtime.h"
#include "utils/hook_engine.h"
#include "utils/maps_watcher.h"
#include "utils/ipc.h"
#include "injector/injector.h"

extern void js_dispatch_hook(int hook_id, HookContext& hctx, bool is_before);
extern bool ipc_hook_install(int hook_id, const std::string& lib,
    const std::string& symbol, uint64_t target_addr);

#define PORT 20847

#include <queue>
#include <mutex>

std::queue<std::string> g_log_queue;
std::mutex              g_log_mutex;

static std::string cmd_log_poll() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_queue.empty()) return "{\"status\":\"ok\",\"msg\":\"\"}";
    std::string msg = g_log_queue.front(); g_log_queue.pop();
    std::string escaped;
    for (char c : msg) {
        if (c == '"')       escaped += "\\\"";
        else if (c == '\\') escaped += "\\\\";
        else if (c == '\n') escaped += "\\n";
        else                escaped += c;
    }
    return "{\"status\":\"ok\",\"msg\":\"" + escaped + "\"}";
}

static void ipc_listener_thread() {
    fprintf(stderr, "[IPC] listener started\n"); fflush(stderr);

    while (true) {
        js_runtime_tick();
        IPCMsg msg{};
        if (!ipc_cb_recv(msg, 1000)) continue;

        if (msg.type == IPCMsgType::READY) {
            send_async("[IPC] hook library connected");
            continue;
        }

        if (msg.type == IPCMsgType::LIB_LOADED_RESP) {
            std::string lib_name = msg.lib;
            uint64_t base = msg.target_addr;
            // payload = path (LIB_LOADED_RESP'te gönderilen full path)
            std::string path = std::string(msg.payload, msg.payload_size);
            fprintf(stderr, "[lib_loaded] %s @ 0x%lx path=%s\n",
                lib_name.c_str(), base, path.c_str());
            fflush(stderr);
            js_notify_lib_loaded(lib_name, base, path);
            continue;
        }

        if (msg.type == IPCMsgType::HOOK_BEFORE || msg.type == IPCMsgType::HOOK_AFTER) {
            bool is_before = (msg.type == IPCMsgType::HOOK_BEFORE);
            HookContext hctx;
            hctx.hook_id = msg.hook_id;
            hctx.ret_val = msg.ret_val;
            hctx.lib = msg.lib;
            hctx.symbol = msg.symbol;
            hctx.target_addr = msg.target_addr;
            for (int i = 0; i < 8; i++) hctx.args[i] = msg.args[i];

            js_dispatch_hook(msg.hook_id, hctx, is_before);

            if (!is_before && hctx.ret_modified) {
                IPCMsg reply{};
                reply.type = IPCMsgType::SET_RET;
                reply.hook_id = msg.hook_id;
                reply.override_val = hctx.ret_new_val;
                ipc_cb_send(reply);
            }
            continue;
        }
    }
}

bool ipc_hook_install(int hook_id, const std::string& lib,
    const std::string& symbol, uint64_t target_addr) {
    IPCMsg msg{};
    msg.type = IPCMsgType::HOOK_INSTALL;
    msg.hook_id = hook_id;
    msg.target_addr = target_addr;
    strncpy(msg.lib, lib.c_str(), 127);
    strncpy(msg.symbol, symbol.c_str(), 127);
    bool ok = ipc_cmd_send(msg);
    if (ok) {
        IPCMsg reply{};
        ipc_cmd_recv(reply, 2000);
    }
    return ok;
}

int main() {
    if (!js_runtime_init()) { std::cerr << "[MARS] JS init failed\n"; return 1; }
    maps_watcher_start();

    if (!ipc_server_start("mars_hook_cmd", "mars_hook_cb"))
        fprintf(stderr, "[IPC] server start failed\n");
    std::thread(ipc_listener_thread).detach();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) { perror("bind");close(server_fd);return 1; }
    if (listen(server_fd, 1) < 0) { perror("listen");close(server_fd);return 1; }

    std::cout << "[MARS Agent-v3] Listening on " << PORT << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;
        set_active_client(client_fd);

        char buf[65536];
        int n = read(client_fd, buf, sizeof(buf) - 1);
        if (n <= 0) { close(client_fd); continue; }
        buf[n] = 0;

        std::string req(buf), res;
        std::string cmd = json_get(req, "cmd");
        std::string data = json_get(req, "data");

        if (cmd == "ping")         res = json_resp("ok", "pong");
        else if (cmd == "ps")           res = cmd_ps_apps();
        else if (cmd == "attach")       res = cmd_attach(data);
        else if (cmd == "spawn")        res = cmd_spawn(data);
        else if (cmd == "resume")       res = cmd_resume(data);
        else if (cmd == "shell")        res = cmd_shell(data);
        else if (cmd == "sysinfo")      res = cmd_get_sysinfo();
        else if (cmd == "read_mem")     res = cmd_read_mem(data);
        else if (cmd == "maps")         res = cmd_get_attached_maps();
        else if (cmd == "libs")         res = cmd_list_libs();
        else if (cmd == "js_load")      res = js_runtime_load(data);
        else if (cmd == "js_eval")      res = js_runtime_eval(data);
        else if (cmd == "hook_install") {
            res = cmd_hook_install(json_get(req, "lib"), json_get(req, "symbol"));
        }
        else if (cmd == "hook_remove") {
            std::string id_str = json_get(req, "hook_id");
            int hook_id = id_str.empty() ? -1 : std::stoi(id_str);
            res = cmd_hook_remove(hook_id);
        }
        else if (cmd == "inject") {
            int pid = get_attached_pid();
            if (pid <= 0) res = json_resp("error", "no attached process");
            else {
                std::string so_path = data;
                std::thread([pid, so_path]() { inject_so(pid, so_path); }).detach();
                res = json_resp("ok", "inject started pid=" + std::to_string(pid));
            }
        }
        else if (cmd == "hook_list")   res = cmd_hook_list();
        else if (cmd == "find_symbol") {
            res = cmd_find_symbol(json_get(req, "lib"), json_get(req, "symbol"));
        }
        else if (cmd == "log_poll")    res = cmd_log_poll();
        else                           res = json_resp("error", "unknown command");

        send(client_fd, res.c_str(), res.size(), 0);
        close(client_fd);
    }

    maps_watcher_stop();
    ipc_server_stop();
    js_runtime_shutdown();
    close(server_fd);
    return 0;
}