#include "command.h"
#include "../utils/json.h"

// Ping
std::string cmd_ping() {
    return json_resp("ok", "pong");
}

// Echo
std::string cmd_echo(const std::string& text) {
    return json_resp("ok", text);
}

// Device Info
std::string cmd_device_info() {
    return "{"
        "\"status\":\"ok\","
        "\"device\":\"Samsung Galaxy A16\","
        "\"arch\":\"arm64\","
        "\"android\":\"14\""
        "}";
}
