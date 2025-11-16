#include "command.h"
#include "../utils/json.h"
#include <array>
#include <cstdio>
#include <string>

// Ortak komut çalýþtýrma fonksiyonu
static std::string run_cmd_sys(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result;

    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) return "popen_failed";

    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }

    pclose(pipe);

    // JSON bozulmasýn diye çift týrnaklarý düzelt
    for (char& c : result)
        if (c == '\"') c = '\'';

    return result;
}

std::string cmd_get_sysinfo() {
    std::string kernel = run_cmd_sys("uname -a");
    std::string cpu = run_cmd_sys("cat /proc/cpuinfo | head -5");
    std::string ram = run_cmd_sys("cat /proc/meminfo | head -2");

    return "{"
        "\"status\":\"ok\","
        "\"kernel\":\"" + kernel + "\","
        "\"cpu\":\"" + cpu + "\","
        "\"ram\":\"" + ram + "\""
        "}";
}
