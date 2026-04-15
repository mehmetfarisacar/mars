#include "command.h"
#include "../utils/json.h"
#include <array>
#include <cstdio>
#include <string>

// shell komutlarýný çalýþtýrmak için ortak fonksiyon
static std::string run_shell(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result = "";

    // stderr'i stdout'a yönlendirme
    std::string fullCmd = cmd + " 2>&1";

    FILE* pipe = popen(fullCmd.c_str(), "r");
    if (!pipe)
        return "popen_failed";

    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }

    pclose(pipe);
    return result;
}

std::string cmd_shell(const std::string& bashCmd) {
    std::string out = run_shell(bashCmd);

    // JSON içinde " ve \ karakterlerinde escape gerekiyor
    for (char& c : out) {
        if (c == '\"') c = '\'';
    }

    return "{\"status\":\"ok\",\"output\":\"" + out + "\"}";
}
