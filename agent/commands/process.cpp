#include "command.h"
#include "../utils/json.h"
#include <array>
#include <cstdio>
#include <string>

// --- ortak shell runner ---
static std::string run_cmd(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result;

    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) return "popen_failed";

    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }

    pclose(pipe);

    // JSON bozulmasýn diye çift týrnaklarý deðiþtir
    for (char& c : result)
        if (c == '\"') c = '\'';

    return result;
}

// ---- ps komutu ----
std::string cmd_ps() {
    std::string out = run_cmd("ps -A");
    return "{\"status\":\"ok\",\"processes\":\"" + out + "\"}";
}

// ---- list_packages ----
std::string cmd_list_packages() {
    std::string out = run_cmd("pm list packages");
    return "{\"status\":\"ok\",\"packages\":\"" + out + "\"}";
}

// ---- kill pid ----
std::string cmd_kill(const std::string& pidStr) {
    run_cmd("kill " + pidStr);
    return json_resp("ok", "process killed");
}

// ---- get_maps pid ----
std::string cmd_get_maps(const std::string& pidStr) {
    std::string out = run_cmd("cat /proc/" + pidStr + "/maps");
    return "{\"status\":\"ok\",\"maps\":\"" + out + "\"}";
}
