#include "command.h"
#include "../utils/json.h"
#include <fstream>
#include <sstream>
#include <set>
#include <string>

// ?????????????????????????????????????????
//  cmd_get_attached_maps
//  /proc/pid/maps içeriðini ham döndür
// ?????????????????????????????????????????
std::string cmd_get_attached_maps() {
    int pid = get_attached_pid();
    if (pid <= 0)
        return json_resp("error", "no attached process");

    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    if (!f.is_open())
        return json_resp("error", "cannot open maps");

    std::stringstream ss;
    ss << f.rdbuf();
    return json_resp("ok", ss.str());
}

// ?????????????????????????????????????????
//  cmd_list_libs
//  Yüklü .so dosyalarýný listele
//  JSON: {"status":"ok","count":N,"libs":[{"name":"...","path":"...","base":"0x..."}]}
// ?????????????????????????????????????????
std::string cmd_list_libs() {
    int pid = get_attached_pid();
    if (pid <= 0)
        return json_resp("error", "no attached process");

    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    if (!f.is_open())
        return json_resp("error", "cannot open maps");

    // Tekrar eden lib'leri filtrele — her lib sadece bir kez (ilk base adresiyle)
    std::set<std::string> seen;

    struct LibEntry {
        std::string name;
        std::string path;
        std::string base;
    };
    std::vector<LibEntry> libs;

    std::string line;
    while (std::getline(f, line)) {
        // Sadece .so içeren satýrlar
        if (line.find(".so") == std::string::npos) continue;

        // Path'i al (son alan)
        size_t path_start = line.rfind(' ');
        if (path_start == std::string::npos) continue;
        std::string path = line.substr(path_start + 1);

        // Boþ veya özel path'leri atla
        if (path.empty() || path[0] != '/') continue;

        // Daha önce eklendiyse geç
        if (seen.count(path)) continue;
        seen.insert(path);

        // Base adresi al (satýr baþý)
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        std::string base = "0x" + line.substr(0, dash);

        // Lib adýný path'den çýkar
        size_t name_start = path.rfind('/');
        std::string name = (name_start != std::string::npos)
            ? path.substr(name_start + 1)
            : path;

        libs.push_back({ name, path, base });
    }

    // JSON çýktýsý oluþtur
    std::ostringstream out;
    out << "{\"status\":\"ok\","
        << "\"count\":" << libs.size() << ","
        << "\"libs\":[";

    for (size_t i = 0; i < libs.size(); i++) {
        if (i) out << ",";
        out << "{"
            << "\"name\":\"" << libs[i].name << "\","
            << "\"path\":\"" << libs[i].path << "\","
            << "\"base\":\"" << libs[i].base << "\""
            << "}";
    }

    out << "]}";
    return out.str();
}