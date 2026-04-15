#ifdef _WIN32
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#define CLR_RESET   "\033[0m"
#define CLR_GREEN   "\033[32m"
#define CLR_GRAY    "\033[90m"
#define CLR_CYAN    "\033[36m"
#define CLR_YELLOW  "\033[33m"
#define CLR_RED     "\033[31m"
#define CLR_MAGENTA "\033[35m"
#define CLR_BOLD    "\033[1m"
#define CLR_WHITE   "\033[97m"

// ─── RPC ────────────────────────────────────────────────────────────────────

static std::string g_ip;
static int         g_port;

static std::string rpc(const std::string& ip, int port, const std::string& payload) {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "{\"status\":\"error\",\"msg\":\"socket failed\"}";
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) {
        closesocket(s); WSACleanup();
        return "{\"status\":\"error\",\"msg\":\"connection failed\"}";
    }
    send(s, payload.c_str(), (int)payload.size(), 0);
    std::string result;
    char buf[65536];
    int n;
    while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0; result += buf;
    }
    closesocket(s); WSACleanup();
    return result;
}

// ─── JSON helpers ────────────────────────────────────────────────────────────

static std::string jval(const std::string& json, const std::string& key) {
    std::string k = "\"" + key + "\"";
    size_t pos = json.find(k);
    if (pos == std::string::npos) return "";
    size_t colon = json.find(":", pos + k.size());
    if (colon == std::string::npos) return "";
    size_t start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return "";
    if (json[start] == '"') {
        size_t end = json.find('"', start + 1);
        return json.substr(start + 1, end - start - 1);
    }
    size_t end = json.find_first_of(",}]", start);
    return json.substr(start, end - start);
}

static bool jok(const std::string& json) {
    return json.find("\"status\":\"ok\"") != std::string::npos;
}

static std::string jescape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"':  o += "\\\""; break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:   o += c;
        }
    }
    return o;
}

// ─── Log stream ──────────────────────────────────────────────────────────────

static std::mutex        g_log_mutex;
static std::atomic<bool> g_repl_running{ false };
static std::string       g_current_input;

// Log satırını REPL prompt'u bozmadan yaz
static void repl_print_log(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    // Prompt satırını sil
    std::cout << "\r\033[2K";
    // Log satırını yaz
    std::cout << CLR_CYAN << "[log] " << CLR_RESET << line << "\n";
    // Prompt'u yeniden çiz
    std::cout << CLR_MAGENTA << CLR_BOLD << "MARS" << CLR_RESET
        << CLR_WHITE << "> " << CLR_RESET
        << g_current_input << std::flush;
}

// Log stream thread - agent'tan sürekli log çeker
static void log_stream_thread() {
    while (g_repl_running) {
        std::string res = rpc(g_ip, g_port, "{\"cmd\":\"log_poll\"}");
        if (jok(res)) {
            std::string msg = jval(res, "msg");
            if (!msg.empty()) {
                repl_print_log(msg);
            }
        }
        Sleep(300);
    }
}

// ─── Print helpers ───────────────────────────────────────────────────────────

static void print_status(const std::string& res) {
    if (jok(res)) {
        std::string msg = jval(res, "msg");
        std::cout << CLR_GREEN << "[ok] " << CLR_RESET << msg << "\n";
    }
    else {
        std::cout << CLR_RED << "[error] " << CLR_RESET << jval(res, "msg") << "\n";
    }
}

static void print_ps(const std::string& json) {
    size_t p = json.find("\"apps\":[");
    if (p == std::string::npos) { std::cout << json << "\n"; return; }
    std::cout << CLR_CYAN
        << std::left << std::setw(8) << "PID"
        << std::setw(50) << "PACKAGE"
        << CLR_RESET << "\n" << std::string(58, '-') << "\n";
    size_t i = p;
    while ((i = json.find('{', i)) != std::string::npos) {
        size_t e = json.find('}', i);
        if (e == std::string::npos) break;
        std::string obj = json.substr(i, e - i + 1);
        size_t pp = obj.find("\"pid\":");
        size_t pk = obj.find("\"package\":\"");
        if (pp == std::string::npos || pk == std::string::npos) { i = e + 1; continue; }
        int pid = std::stoi(obj.substr(pp + 6));
        size_t ke = obj.find('"', pk + 11);
        std::string pkg = obj.substr(pk + 11, ke - (pk + 11));
        bool running = pid != -1;
        std::cout << (running ? CLR_GREEN : CLR_GRAY)
            << std::setw(8) << (running ? std::to_string(pid) : "-")
            << std::setw(50) << pkg
            << CLR_RESET << "\n";
        i = e + 1;
    }
}

static void print_hooks(const std::string& json) {
    size_t p = json.find("\"hooks\":[");
    if (p == std::string::npos) { std::cout << json << "\n"; return; }
    std::cout << CLR_CYAN << "Active hooks: " << jval(json, "count") << CLR_RESET << "\n"
        << std::string(72, '-') << "\n"
        << CLR_CYAN
        << std::left
        << std::setw(6) << "ID"
        << std::setw(25) << "LIB"
        << std::setw(25) << "SYMBOL"
        << std::setw(18) << "ADDR"
        << CLR_RESET << "\n" << std::string(72, '-') << "\n";
    size_t i = p;
    while ((i = json.find('{', i)) != std::string::npos) {
        size_t e = json.find('}', i);
        if (e == std::string::npos) break;
        std::string obj = json.substr(i, e - i + 1);
        std::string id = jval(obj, "id");
        std::string lib = jval(obj, "lib");
        std::string symbol = jval(obj, "symbol");
        std::string addr = jval(obj, "addr");
        if (!id.empty())
            std::cout << CLR_GREEN
            << std::setw(6) << id
            << std::setw(25) << lib
            << std::setw(25) << symbol
            << std::setw(18) << addr
            << CLR_RESET << "\n";
        i = e + 1;
    }
}

static void print_libs(const std::string& json) {
    size_t p = json.find("\"libs\":[");
    if (p == std::string::npos) { std::cout << json << "\n"; return; }
    std::cout << CLR_CYAN << "Loaded libs: " << jval(json, "count") << CLR_RESET << "\n"
        << std::string(80, '-') << "\n"
        << CLR_CYAN
        << std::left
        << std::setw(35) << "NAME"
        << std::setw(15) << "BASE"
        << "PATH"
        << CLR_RESET << "\n" << std::string(80, '-') << "\n";
    size_t i = p;
    while ((i = json.find('{', i)) != std::string::npos) {
        size_t e = json.find('}', i);
        if (e == std::string::npos) break;
        std::string obj = json.substr(i, e - i + 1);
        std::string name = jval(obj, "name");
        std::string base = jval(obj, "base");
        std::string path = jval(obj, "path");
        if (!name.empty())
            std::cout << CLR_GREEN
            << std::setw(35) << name
            << std::setw(15) << base
            << CLR_GRAY << path
            << CLR_RESET << "\n";
        i = e + 1;
    }
}

// ─── REPL komut işleyici ─────────────────────────────────────────────────────

static void repl_exec(const std::string& line) {
    if (line.empty()) return;

    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "exit" || cmd == "quit") {
        g_repl_running = false;
        return;
    }
    if (cmd == "help") {
        std::cout << CLR_CYAN << "\nCommands:\n" << CLR_RESET
            << "  ps                         Process listesi\n"
            << "  attach  <package>          Process'e attach ol\n"
            << "  spawn   <package>          Uygulamayı başlat\n"
            << "  inject  <so_path>          SO inject et\n"
            << "  libs                       Yüklü lib'leri listele\n"
            << "  hook    <lib> <symbol>     Fonksiyonu hookla\n"
            << "  hooks                      Aktif hooklar\n"
            << "  unhook  <id>               Hook kaldır\n"
            << "  symbol  <lib> <sym>        Sembol adresini bul\n"
            << "  load    <script.mars.js>   JS script yükle\n"
            << "  eval    <kod>              JS kodu çalıştır\n"
            << "  mem     <addr> <size>      Memory oku\n"
            << "  ping                       Ping\n"
            << "  exit                       Çıkış\n\n";
        return;
    }
    if (cmd == "ping") {
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"ping\"}"));
        return;
    }
    if (cmd == "ps") {
        print_ps(rpc(g_ip, g_port, "{\"cmd\":\"ps\"}"));
        return;
    }
    if (cmd == "attach") {
        std::string pkg; iss >> pkg;
        if (pkg.empty()) { std::cout << "Usage: attach <package>\n"; return; }
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"attach\",\"data\":\"" + pkg + "\"}"));
        return;
    }
    if (cmd == "spawn") {
        std::string pkg; iss >> pkg;
        if (pkg.empty()) { std::cout << "Usage: spawn <package>\n"; return; }
        std::string res = rpc(g_ip, g_port, "{\"cmd\":\"spawn\",\"data\":\"" + pkg + "\"}");
        if (jok(res))
            std::cout << CLR_GREEN << "[ok] " << CLR_RESET
            << "spawned " << pkg << "  pid=" << jval(res, "pid") << "\n";
        else
            print_status(res);
        return;
    }
    if (cmd == "inject") {
        std::string path; iss >> path;
        if (path.empty()) { std::cout << "Usage: inject <so_path>\n"; return; }
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"inject\",\"data\":\"" + path + "\"}"));
        return;
    }
    if (cmd == "libs") {
        print_libs(rpc(g_ip, g_port, "{\"cmd\":\"libs\"}"));
        return;
    }
    if (cmd == "symbol") {
        std::string lib, sym; iss >> lib >> sym;
        if (lib.empty() || sym.empty()) { std::cout << "Usage: symbol <lib> <symbol>\n"; return; }
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"find_symbol\",\"lib\":\"" + lib + "\",\"symbol\":\"" + sym + "\"}");
        if (jok(res))
            std::cout << CLR_GREEN << "[ok] " << CLR_RESET
            << lib << "::" << sym << " -> "
            << CLR_YELLOW << jval(res, "addr") << CLR_RESET << "\n";
        else
            print_status(res);
        return;
    }
    if (cmd == "hook") {
        std::string lib, sym; iss >> lib >> sym;
        if (lib.empty() || sym.empty()) { std::cout << "Usage: hook <lib> <symbol>\n"; return; }
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"hook_install\",\"lib\":\"" + lib + "\",\"symbol\":\"" + sym + "\"}");
        if (jok(res))
            std::cout << CLR_GREEN << "[hooked] " << CLR_RESET
            << lib << "::" << sym
            << " @ " << CLR_YELLOW << jval(res, "addr") << CLR_RESET
            << " (id=" << jval(res, "hook_id") << ")\n";
        else
            print_status(res);
        return;
    }
    if (cmd == "hooks") {
        print_hooks(rpc(g_ip, g_port, "{\"cmd\":\"hook_list\"}"));
        return;
    }
    if (cmd == "unhook") {
        std::string id; iss >> id;
        if (id.empty()) { std::cout << "Usage: unhook <id>\n"; return; }
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"hook_remove\",\"hook_id\":" + id + "}"));
        return;
    }
    if (cmd == "load") {
        std::string file; iss >> file;
        if (file.empty()) { std::cout << "Usage: load <script.mars.js>\n"; return; }
        std::ifstream f(file);
        if (!f.is_open()) {
            std::cout << CLR_RED << "[error] " << CLR_RESET << "cannot open: " << file << "\n";
            return;
        }
        std::ostringstream ss; ss << f.rdbuf();
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"js_load\",\"data\":\"" + jescape(ss.str()) + "\"}"));
        return;
    }
    if (cmd == "eval") {
        std::string rest;
        std::getline(iss >> std::ws, rest);
        if (rest.empty()) { std::cout << "Usage: eval <code>\n"; return; }
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"js_eval\",\"data\":\"" + jescape(rest) + "\"}"));
        return;
    }
    if (cmd == "mem") {
        std::string addr, size; iss >> addr >> size;
        if (addr.empty() || size.empty()) { std::cout << "Usage: mem <addr> <size>\n"; return; }
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"read_mem\",\"data\":{\"addr\":\"" + addr + "\",\"size\":\"" + size + "\"}}");
        if (jok(res))
            std::cout << CLR_YELLOW << jval(res, "msg") << CLR_RESET << "\n";
        else
            print_status(res);
        return;
    }

    std::cout << CLR_RED << "[error] " << CLR_RESET << "unknown: " << cmd
        << "  (type 'help')\n";
}

// ─── Banner ──────────────────────────────────────────────────────────────────

static void print_banner(const std::string& ip, int port) {
    std::cout << CLR_BOLD << "\033[91m\n"
        << "  __  __    _    ____  ____  \n"
        << " |  \\/  |  / \\  |  _ \\/ ___| \n"
        << " | |\\/| | / _ \\ | |_) \\___ \\ \n"
        << " | |  | |/ ___ \\|  _ < ___) |\n"
        << " |_|  |_/_/   \\_\\_| \\_\\____/ \n"
        << "\n" << CLR_RESET;
    std::cout << CLR_GRAY << "  Mobile Application Runtime Security\n" << CLR_RESET;
    std::cout << CLR_CYAN << "  Connected to " << CLR_WHITE << ip << ":" << port << CLR_RESET << "\n";
    std::cout << CLR_GRAY << "  Type 'help' for commands, 'exit' to quit\n\n" << CLR_RESET;
}

// ─── REPL loop ───────────────────────────────────────────────────────────────

static void run_repl() {
    g_repl_running = true;

    // Log stream thread başlat
    std::thread log_thread(log_stream_thread);

    // Windows konsol - ANSI escape aktif et
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    print_banner(g_ip, g_port);

    while (g_repl_running) {
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "\033[32m" << CLR_BOLD << "MARS" << CLR_RESET
                << "\033[32m" << "> " << CLR_RESET << std::flush;
            g_current_input = "";
        }

        std::string line;
        if (!std::getline(std::cin, line)) break;

        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            g_current_input = "";
        }

        repl_exec(line);
    }

    g_repl_running = false;
    log_thread.join();
}

// ─── Legacy single-command mode ──────────────────────────────────────────────

static void print_usage() {
    std::cout << CLR_CYAN << "\nMARS CLI v3\n" << CLR_RESET
        << "Usage: mars-cli-v3.exe <ip> <port> [command] [args...]\n\n"
        << "  No command → interactive REPL mode\n\n"
        << "Commands:\n"
        << "  ping\n"
        << "  ps\n"
        << "  attach  <package>\n"
        << "  spawn   <package>\n"
        << "  run     <package> <script>\n"
        << "  inject  <so_path>\n"
        << "  libs\n"
        << "  symbol  <lib> <symbol>\n"
        << "  hook    <lib> <symbol>\n"
        << "  hooks\n"
        << "  unhook  <hook_id>\n"
        << "  js_load <dosya.mars.js>\n"
        << "  js_eval <kod>\n"
        << "  mem     <addr> <size>\n\n";
}

// ─── main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Windows konsol ANSI
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    if (argc < 3) { print_usage(); return 0; }

    g_ip = argv[1];
    g_port = std::stoi(argv[2]);

    // Sadece ip:port verilmişse → REPL
    if (argc == 3) {
        run_repl();
        return 0;
    }

    std::string cmd = argv[3];

    // Legacy komut modu
    if (cmd == "ping") {
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"ping\"}"));
    }
    else if (cmd == "ps") {
        print_ps(rpc(g_ip, g_port, "{\"cmd\":\"ps\"}"));
    }
    else if (cmd == "attach") {
        if (argc < 5) { std::cout << "Usage: attach <package>\n"; return 1; }
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"attach\",\"data\":\"" + std::string(argv[4]) + "\"}"));
    }
    else if (cmd == "spawn") {
        if (argc < 5) { std::cout << "Usage: spawn <package>\n"; return 1; }
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"spawn\",\"data\":\"" + std::string(argv[4]) + "\"}"));
    }
    else if (cmd == "inject") {
        if (argc < 5) { std::cout << "Usage: inject <so_path>\n"; return 1; }
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"inject\",\"data\":\"" + std::string(argv[4]) + "\"}"));
    }
    else if (cmd == "run") {
        if (argc < 6) { std::cout << "Usage: run <package> <script.mars.js>\n"; return 1; }
        std::string pkg = argv[4], script = argv[5];
        std::cout << CLR_CYAN << "[run] " << CLR_RESET << "Spawning " << pkg << "...\n";
        std::string spawn_res = rpc(g_ip, g_port, "{\"cmd\":\"spawn\",\"data\":\"" + pkg + "\"}");
        if (!jok(spawn_res)) { print_status(spawn_res); return 1; }
        std::cout << CLR_GREEN << "[run] " << CLR_RESET << "PID: " << jval(spawn_res, "pid") << "\n";
        std::ifstream sf(script);
        if (!sf.is_open()) {
            std::cout << CLR_RED << "[error] " << CLR_RESET << "cannot open: " << script << "\n";
            return 1;
        }
        std::ostringstream ss; ss << sf.rdbuf();
        std::cout << CLR_CYAN << "[run] " << CLR_RESET << "Loading " << script << "...\n";
        print_status(rpc(g_ip, g_port, "{\"cmd\":\"js_load\",\"data\":\"" + jescape(ss.str()) + "\"}"));
    }
    else if (cmd == "libs") {
        print_libs(rpc(g_ip, g_port, "{\"cmd\":\"libs\"}"));
    }
    else if (cmd == "symbol") {
        if (argc < 6) { std::cout << "Usage: symbol <lib> <symbol>\n"; return 1; }
        std::string lib = argv[4], sym = argv[5];
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"find_symbol\",\"lib\":\"" + lib + "\",\"symbol\":\"" + sym + "\"}");
        if (jok(res))
            std::cout << CLR_GREEN << "[ok] " << CLR_RESET
            << lib << "::" << sym << " -> "
            << CLR_YELLOW << jval(res, "addr") << CLR_RESET << "\n";
        else print_status(res);
    }
    else if (cmd == "hook") {
        if (argc < 6) { std::cout << "Usage: hook <lib> <symbol>\n"; return 1; }
        std::string lib = argv[4], sym = argv[5];
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"hook_install\",\"lib\":\"" + lib + "\",\"symbol\":\"" + sym + "\"}");
        if (jok(res))
            std::cout << CLR_GREEN << "[hooked] " << CLR_RESET
            << lib << "::" << sym
            << " @ " << CLR_YELLOW << jval(res, "addr") << CLR_RESET
            << " (id=" << jval(res, "hook_id") << ")\n";
        else print_status(res);
    }
    else if (cmd == "hooks") {
        print_hooks(rpc(g_ip, g_port, "{\"cmd\":\"hook_list\"}"));
    }
    else if (cmd == "unhook") {
        if (argc < 5) { std::cout << "Usage: unhook <hook_id>\n"; return 1; }
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"hook_remove\",\"hook_id\":" + std::string(argv[4]) + "}"));
    }
    else if (cmd == "js_load") {
        if (argc < 5) { std::cout << "Usage: js_load <file.mars.js>\n"; return 1; }
        std::ifstream f(argv[4]);
        if (!f.is_open()) {
            std::cout << CLR_RED << "[error] " << CLR_RESET << "cannot open: " << argv[4] << "\n";
            return 1;
        }
        std::ostringstream ss; ss << f.rdbuf();
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"js_load\",\"data\":\"" + jescape(ss.str()) + "\"}"));
    }
    else if (cmd == "js_eval") {
        if (argc < 5) { std::cout << "Usage: js_eval <code>\n"; return 1; }
        print_status(rpc(g_ip, g_port,
            "{\"cmd\":\"js_eval\",\"data\":\"" + jescape(argv[4]) + "\"}"));
    }
    else if (cmd == "mem") {
        if (argc < 6) { std::cout << "Usage: mem <addr> <size>\n"; return 1; }
        std::string res = rpc(g_ip, g_port,
            "{\"cmd\":\"read_mem\",\"data\":{\"addr\":\"" +
            std::string(argv[4]) + "\",\"size\":\"" + std::string(argv[5]) + "\"}}");
        if (jok(res))
            std::cout << CLR_YELLOW << jval(res, "msg") << CLR_RESET << "\n";
        else print_status(res);
    }
    else if (cmd == "repl") {
        run_repl();
    }
    else {
        std::cout << CLR_RED << "[error] " << CLR_RESET << "unknown command: " << cmd << "\n";
        print_usage();
        return 1;
    }

    return 0;
}

#include <windows.h>
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    return main(__argc, __argv);
}
#endif