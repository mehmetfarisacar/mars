#include "command.h"
#include "../utils/json.h"
#include <fstream>
#include <sstream>

// ---- READ FILE ----
std::string cmd_read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return json_resp("error", "cannot open file");
    }

    std::stringstream ss;
    ss << file.rdbuf();
    file.close();

    // JSON kaçýþ iþlemi (týrnaklarý bozmasýn)
    std::string content = ss.str();
    for (char& c : content) {
        if (c == '\"') c = '\'';
    }

    return "{\"status\":\"ok\",\"data\":\"" + content + "\"}";
}

// ---- WRITE FILE ----
std::string cmd_write_file(const std::string& path, const std::string& data) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return json_resp("error", "cannot write file");
    }

    file << data;
    file.close();

    return json_resp("ok", "file written");
}
