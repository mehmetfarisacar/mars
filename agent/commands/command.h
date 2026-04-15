#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ── attach ──
std::string cmd_attach(const std::string& packageName);
int  get_attached_pid();
void set_attached_pid(int pid);

// ── async logging ──
void set_active_client(int fd);
void send_async(const std::string& msg);

// ── memory ──
std::string cmd_read_mem(const std::string& data);

// ── ps / spawn ──
std::string cmd_ps_apps();
std::string cmd_spawn(const std::string& package);

// ── shell / sysinfo ──
std::string cmd_shell(const std::string& bashCmd);
std::string cmd_get_sysinfo();

// ── maps / libs ──
std::string cmd_get_attached_maps();
std::string cmd_list_libs();

// ── spawn ──
std::string cmd_spawn(const std::string& packageName);
std::string cmd_resume(const std::string& data);

// ── hook ──
std::string cmd_hook_install(const std::string& lib, const std::string& symbol);
std::string cmd_hook_remove(int hook_id);
std::string cmd_hook_list();
std::string cmd_find_symbol(const std::string& lib, const std::string& symbol);