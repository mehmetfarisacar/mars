#pragma once
#include <cstdint>
#include <string>

// Low-level read primitive: reads from /proc/<pid>/mem for currently attached pid.
// Returns true on success, and fills out bytes into outBytes.
bool read_mem_bytes(uint64_t addr, size_t size, std::string& outBytes);
