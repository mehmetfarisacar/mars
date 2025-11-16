#pragma once
#include <string>

// Basic commands
std::string cmd_ping();
std::string cmd_echo(const std::string& text);
std::string cmd_device_info();

// Shell
std::string cmd_shell(const std::string& bashCmd);

// Filesystem
std::string cmd_read_file(const std::string& path);
std::string cmd_write_file(const std::string& path, const std::string& data);

// Process & system
std::string cmd_ps();
std::string cmd_list_packages();
std::string cmd_kill(const std::string& pidStr);
std::string cmd_get_maps(const std::string& pidStr);

std::string cmd_get_sysinfo();
