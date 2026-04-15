#include "command.h"
#include "../utils/json.h"
#include <cstdio>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <unistd.h>

/*
 * ps -A -o PID,NAME
 * Android toybox uyumlu
 */
static std::map<std::string, int> get_running_processes() {
    std::map<std::string, int> out;
    FILE* pipe = popen("ps -A -o PID,NAME", "r");
    if (!pipe) return out;
    char line[512];
    fgets(line, sizeof(line), pipe); // header
    while (fgets(line, sizeof(line), pipe)) {
        std::istringstream iss(line);
        int pid;
        std::string name;
        iss >> pid >> name;
        if (!name.empty() && pid > 0) {
            out[name] = pid;
        }
    }
    pclose(pipe);
    return out;
}

/*
 * pm list packages -3
 * third-party apps only
 */
static std::vector<std::string> get_all_packages() {
    std::vector<std::string> out;
    FILE* pipe = popen("pm list packages -3", "r");
    if (!pipe) return out;
    char line[512];
    while (fgets(line, sizeof(line), pipe)) {
        std::string l(line);
        if (l.rfind("package:", 0) == 0) {
            std::string pkg = l.substr(8);
            pkg.erase(pkg.find_last_not_of("\n\r") + 1);
            out.push_back(pkg);
        }
    }
    pclose(pipe);
    return out;
}

/*
 * RPC: ps
 */
std::string cmd_ps_apps() {
    auto running = get_running_processes();
    auto packages = get_all_packages();

    struct App { int pid; std::string pkg; };
    std::vector<App> running_apps, stopped_apps;

    for (auto& pkg : packages) {
        auto it = running.find(pkg);
        if (it != running.end())
            running_apps.push_back({ it->second, pkg });
        else
            stopped_apps.push_back({ -1, pkg });
    }

    std::sort(running_apps.begin(), running_apps.end(),
        [](const App& a, const App& b) { return a.pid < b.pid; });

    std::ostringstream out;
    out << "{ \"status\":\"ok\", \"apps\":[";
    bool first = true;
    auto emit = [&](const App& a) {
        if (!first) out << ",";
        first = false;
        out << "{\"pid\":" << a.pid << ",\"package\":\"" << a.pkg << "\"}";
        };
    for (auto& a : running_apps) emit(a);
    for (auto& a : stopped_apps) emit(a);
    out << "]}";
    return out.str();
}