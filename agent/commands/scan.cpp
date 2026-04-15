#include "command.h"
#include "../utils/json.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include <unistd.h>
#include <fcntl.h>

extern int get_attached_pid();

static std::string to_hex_u64(uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::nouppercase << v;
    return oss.str();
}

// limits
static const size_t kMaxRegionBytes = 16 * 1024 * 1024; // 16MB
static const size_t kChunkSize = 256 * 1024;           // 256KB
static const size_t kMaxHits = 2000;

// ================================
// CORE SCAN FUNCTION (FOR JS)
// ================================
std::vector<uint64_t> scan_hits(const std::string& needle) {

    std::vector<uint64_t> hits;

    int pid = get_attached_pid();
    if (pid <= 0 || needle.empty())
        return hits;

    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    std::string memPath = "/proc/" + std::to_string(pid) + "/mem";

    FILE* maps = fopen(mapsPath.c_str(), "r");
    if (!maps)
        return hits;

    int memfd = open(memPath.c_str(), O_RDONLY);
    if (memfd < 0) {
        fclose(maps);
        return hits;
    }

    char line[1024];

    while (fgets(line, sizeof(line), maps)) {

        unsigned long start = 0, end = 0;
        char perms[8] = { 0 };

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        // only readable
        if (perms[0] != 'r')
            continue;

        uint64_t regionStart = (uint64_t)start;
        uint64_t regionEnd = (uint64_t)end;
        uint64_t regionSize = regionEnd - regionStart;
        if (regionSize == 0)
            continue;

        if (regionSize > kMaxRegionBytes)
            regionSize = kMaxRegionBytes;

        std::vector<uint8_t> chunk(kChunkSize + needle.size());
        size_t overlap = needle.size() > 0 ? (needle.size() - 1) : 0;

        uint64_t cursor = regionStart;
        uint64_t remain = regionSize;

        while (remain > 0) {
            size_t toRead = remain > kChunkSize ? kChunkSize : (size_t)remain;

            size_t prefix = 0;
            if (cursor != regionStart && overlap > 0)
                prefix = overlap;

            ssize_t r = pread64(memfd, chunk.data() + prefix, toRead, (off64_t)cursor);
            if (r <= 0)
                break;

            size_t total = (size_t)r + prefix;

            for (size_t i = 0; i + needle.size() <= total; i++) {
                if (memcmp(chunk.data() + i, needle.data(), needle.size()) == 0) {
                    hits.push_back(cursor - prefix + i);
                    if (hits.size() >= kMaxHits)
                        break;
                }
            }
            if (hits.size() >= kMaxHits)
                break;

            if (overlap > 0 && total >= overlap) {
                memmove(chunk.data(), chunk.data() + (total - overlap), overlap);
            }

            cursor += (uint64_t)r;
            remain -= (uint64_t)r;

            if ((size_t)r < toRead)
                break;
        }

        if (hits.size() >= kMaxHits)
            break;
    }

    close(memfd);
    fclose(maps);

    return hits;
}

// ================================
// JSON RPC VERSION (CLI)
// ================================
std::string cmd_scan_str(const std::string& needle)
{
    auto hits = scan_hits(needle);

    std::ostringstream out;
    out << "{\"status\":\"ok\",\"needle\":\"";
    out << needle;
    out << "\",\"count\":" << hits.size() << ",\"hits\":[";

    for (size_t i = 0; i < hits.size(); i++) {
        out << "\"" << to_hex_u64(hits[i]) << "\"";
        if (i + 1 < hits.size())
            out << ",";
    }
    out << "]}";

    return out.str();
}
