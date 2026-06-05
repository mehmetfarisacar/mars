#include "maps_watcher.h"
#include "../commands/command.h"
#include "js_runtime.h"
#include <thread>
#include <chrono>
#include <fstream>
#include <string>
#include <set>
#include <atomic>

static std::atomic<bool> g_running{ false };
static std::thread g_thread;

void maps_watcher_start() {
    if (g_running.load()) return;
    g_running = true;
    g_thread = std::thread([]() {
        std::set<std::string> seen_libs;
        int last_pid = -1;
        while (g_running.load()) {
            int pid = get_attached_pid();
            if (pid != last_pid) { seen_libs.clear(); last_pid = pid; }
            if (pid > 0) {
                std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
                std::ifstream f(maps_path);
                std::string line;
                while (std::getline(f, line)) {
                    if (line.find(".so") == std::string::npos) continue;
                    size_t path_start = line.rfind(' ');
                    if (path_start == std::string::npos) continue;
                    std::string path = line.substr(path_start + 1);
                    if (path.empty() || path[0] != '/') continue;
                    if (seen_libs.count(path)) continue;
                    seen_libs.insert(path);

                    uint64_t base = 0;
                    sscanf(line.c_str(), "%lx", &base);

                    size_t slash = path.rfind('/');
                    std::string name = (slash != std::string::npos)
                        ? path.substr(slash + 1) : path;

                    js_notify_lib_loaded(name, base, path);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        });
    g_thread.detach();
}

void maps_watcher_stop() { g_running = false; }