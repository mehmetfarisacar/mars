#pragma once
#include <string>
#include <cstdint>

// ─── Maksimum payload boyutu ───
// MODULE_LIST_RESP birden fazla modül döndüreceği için büyük payload lazım
static constexpr size_t IPC_PAYLOAD_SIZE = 8192;

enum class IPCMsgType : uint32_t {
    // Mevcut hook mesajları
    HOOK_BEFORE = 1,
    HOOK_AFTER = 2,
    SET_RET = 3,
    SET_ARG = 4,
    HOOK_INSTALL = 5,
    HOOK_REMOVE = 6,
    READY = 7,

    // YENİ — process-içi modül/sembol sorgulama
    // Agent → SO: "yüklü modülleri listele"
    MODULE_LIST_REQ = 8,
    // SO → Agent: modül listesi (payload: JSON)
    MODULE_LIST_RESP = 9,
    // Agent → SO: "bu lib'de bu sembolü bul"
    FIND_SYMBOL_REQ = 10,
    // SO → Agent: sembol adresi (target_addr alanında)
    FIND_SYMBOL_RESP = 11,
    // Agent → SO: "bu lib yüklendi mi? (polling)"
    LIB_LOADED_REQ = 12,
    // SO → Agent: lib yüklü/değil + base adres
    LIB_LOADED_RESP = 13,
};

struct IPCMsg {
    IPCMsgType type;
    int        hook_id;
    uint64_t   args[8];
    uint64_t   ret_val;
    uint64_t   override_val;
    uint64_t   target_addr;
    char       symbol[128];
    char       lib[128];

    // YENİ — büyük veri transferi için payload
    // MODULE_LIST_RESP: JSON string (modül listesi)
    // FIND_SYMBOL_RESP: boş (target_addr kullanılır)
    uint32_t   payload_size;
    char       payload[IPC_PAYLOAD_SIZE];
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