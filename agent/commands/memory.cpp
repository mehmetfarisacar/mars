#include "command.h"
#include "memory.h"
#include "../utils/json.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <iomanip>

// ---------------- internal helpers ----------------
static std::string hex_dump(const std::string& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < bytes.size(); i++) {
        if (i) oss << " ";
        oss << std::setw(2) << (static_cast<unsigned int>(static_cast<unsigned char>(bytes[i])));
    }
    return oss.str();
}

// ---------------- low-level reader ----------------
bool read_mem_bytes(uint64_t addr, size_t size, std::string& outBytes) {
    outBytes.clear();

    int pid = get_attached_pid();
    if (pid <= 0) return false;

    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    std::string buf;
    buf.resize(size);

    ssize_t n = pread64(fd, buf.data(), size, static_cast<off64_t>(addr));
    close(fd);

    if (n <= 0) return false;
    buf.resize(static_cast<size_t>(n));
    outBytes = buf;
    return true;
}

// ---------------- RPC cmd: read_mem ----------------
// expected input JSON (string):
//   {"addr":"0x7f....","size":"64"}  or {"addr":"12345","size":"64"}
// returns:
//   {"status":"ok","msg":"<hex dump>"}  OR {"status":"error","msg":"..."}
std::string cmd_read_mem(const std::string& data) {
    std::string addrStr = json_get(data, "addr");
    std::string sizeStr = json_get(data, "size");

    if (addrStr.empty() || sizeStr.empty()) {
        return json_resp("error", "read_mem expects {addr,size}");
    }

    uint64_t addr = 0;
    try {
        // allow "0x..." or decimal
        if (addrStr.rfind("0x", 0) == 0 || addrStr.rfind("0X", 0) == 0)
            addr = std::stoull(addrStr, nullptr, 16);
        else
            addr = std::stoull(addrStr, nullptr, 10);
    }
    catch (...) {
        return json_resp("error", "invalid addr");
    }

    size_t size = 0;
    try {
        size = static_cast<size_t>(std::stoul(sizeStr, nullptr, 10));
    }
    catch (...) {
        return json_resp("error", "invalid size");
    }

    if (size == 0 || size > (1024 * 1024)) {
        return json_resp("error", "size must be 1..1048576");
    }

    std::string bytes;
    if (!read_mem_bytes(addr, size, bytes)) {
        return json_resp("error", "pread64 failed (permission? unmapped?)");
    }

    return json_resp("ok", hex_dump(bytes));
}
