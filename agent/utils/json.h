#pragma once
#include <string>

inline std::string json_get(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";

    size_t colon = json.find(":", pos);
    size_t q1 = json.find("\"", colon + 1);
    size_t q2 = json.find("\"", q1 + 1);

    if (q1 == std::string::npos || q2 == std::string::npos) return "";
    return json.substr(q1 + 1, q2 - q1 - 1);
}

inline std::string json_resp(const std::string& status, const std::string& msg) {
    return "{\"status\":\"" + status + "\",\"msg\":\"" + msg + "\"}";
}
