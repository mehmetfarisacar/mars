#pragma once
#include <string>
#include <cstdint>

enum class IPCMsgType : uint32_t {
    HOOK_BEFORE = 1,
    HOOK_AFTER = 2,
    SET_RET = 3,
    SET_ARG = 4,
    HOOK_INSTALL = 5,
    HOOK_REMOVE = 6,
    READY = 7,
};

struct IPCMsg {
    IPCMsgType type;
    int        hook_id;
    uint64_t   args[8];
    uint64_t   ret_val;
    uint64_t   override_val;
    uint64_t   target_addr;  // hook edilecek adres (agent'ın dlsym sonucu)
    char       symbol[128];
    char       lib[128];
};

// Agent (server)
bool ipc_server_start(const std::string& cmd_path, const std::string& cb_path);
void ipc_server_stop();
bool ipc_cmd_send(const IPCMsg& msg);
bool ipc_cmd_recv(IPCMsg& msg, int timeout_ms = 2000);
bool ipc_cb_recv(IPCMsg& msg, int timeout_ms = 10000);
bool ipc_cb_send(const IPCMsg& msg);

// SO (client)
bool ipc_client_connect(const std::string& cmd_path, const std::string& cb_path);
void ipc_client_disconnect();
bool ipc_client_cmd_recv(IPCMsg& msg, int timeout_ms = 5000);
bool ipc_client_cmd_send(const IPCMsg& msg);
bool ipc_client_cb_send(const IPCMsg& msg);
bool ipc_client_cb_recv(IPCMsg& msg, int timeout_ms = 200);