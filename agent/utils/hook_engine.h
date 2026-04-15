#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

struct HookContext {
    int      hook_id;
    uint64_t args[8];
    uint64_t ret_val;

    bool     ret_modified;
    uint64_t ret_new_val;

    bool     arg_modified[8];
    uint64_t arg_new_val[8];

    std::string lib;
    std::string symbol;
    uint64_t    target_addr;

    HookContext() {
        hook_id = -1;
        ret_modified = false;
        ret_new_val = 0;
        ret_val = 0;
        target_addr = 0;
        for (int i = 0; i < 8; i++) {
            args[i] = 0;
            arg_modified[i] = false;
            arg_new_val[i] = 0;
        }
    }
};

struct HookEntry {
    int      hook_id;
    uint64_t target_addr;
    uint8_t  original_bytes[8];
    uint64_t trampoline_addr;
    uint64_t override_flag_addr;  // remote page'de flag
    uint64_t override_val_addr;   // remote page'de yeni x0
    std::string lib;
    std::string symbol;
};

uint64_t find_symbol_addr(int pid,
    const std::string& lib_name,
    const std::string& symbol_name);

int  hook_install(int pid,
    const std::string& lib,
    const std::string& symbol,
    uint64_t target_addr);

bool hook_remove(int hook_id);
bool hook_set_ret(int hook_id, uint64_t new_ret);
bool hook_clear_ret(int hook_id);

std::vector<HookEntry> hook_list_all();
HookEntry* hook_find(int hook_id);