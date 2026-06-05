// ═══════════════════════════════════════════════════════
//  mars_hook.so — v7
//
//  v6'dan farkı:
//  - g_apk_offset_cache global yapıldı
//  - MODULE_LIST_REQ handler dl_iterate_phdr tabanlı
//  - module.find("liba0x9.so") artık çalışır
// ═══════════════════════════════════════════════════════
#include "../utils/ipc.h"
#include <cstdio>
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "mars_hook", __VA_ARGS__)
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <link.h>

#define IPC_CMD_PATH "mars_hook_cmd"
#define IPC_CB_PATH  "mars_hook_cb"

struct InternalHook {
    int      hook_id;
    uint64_t target_addr;
    uint8_t  orig_bytes[16];
    uint64_t trampoline_addr;
    char     lib[128];
    char     symbol[128];
};
static std::vector<InternalHook> g_hooks;
static std::mutex                g_hooks_mutex;

// ═══════════════════════════════════════════════════════
//  GLOBAL APK OFFSET CACHE
//  lib_watcher_thread ve command_loop paylaşır
// ═══════════════════════════════════════════════════════
static std::map<std::string, std::map<uint64_t, std::string>> g_apk_offset_cache;
static std::mutex g_apk_cache_mutex;

// ═══════════════════════════════════════════════════════
//  MODÜL BİLGİSİ
// ═══════════════════════════════════════════════════════
struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t    base;
};

static std::vector<ModuleInfo> get_loaded_modules_from_maps() {
    std::vector<ModuleInfo> result;
    std::map<std::string, ModuleInfo> seen;
    std::ifstream f("/proc/self/maps");
    if (!f.is_open()) return result;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("r-xp") == std::string::npos &&
            line.find("r--p") == std::string::npos) continue;
        size_t path_start = line.rfind(' ');
        if (path_start == std::string::npos) continue;
        std::string path = line.substr(path_start + 1);
        if (path.empty() || path[0] != '/') continue;
        uint64_t base = 0;
        sscanf(line.c_str(), "%lx", &base);
        if (!base) continue;
        std::string name;
        size_t excl = path.rfind('!');
        if (excl != std::string::npos) {
            std::string inner = path.substr(excl + 1);
            size_t slash = inner.rfind('/');
            name = (slash != std::string::npos) ? inner.substr(slash + 1) : inner;
        }
        else {
            size_t slash = path.rfind('/');
            name = (slash != std::string::npos) ? path.substr(slash + 1) : path;
        }
        if (name.empty()) continue;
        auto it = seen.find(path);
        if (it == seen.end()) seen[path] = { name, path, base };
        else if (base < it->second.base) it->second.base = base;
    }
    for (auto& [path, info] : seen) result.push_back(info);
    return result;
}

// ═══════════════════════════════════════════════════════
//  APK ZIP PARSE — offset → lib_name map
// ═══════════════════════════════════════════════════════
static std::map<uint64_t, std::string> build_apk_offset_map(const std::string& apk_path) {
    std::map<uint64_t, std::string> result;
    struct __attribute__((packed)) EOCD { uint32_t sig; uint16_t d, sd, ed, et; uint32_t cs, co; uint16_t cl; };
    struct __attribute__((packed)) CD { uint32_t sig; uint16_t vm, vn, fl, cm, mt, md; uint32_t crc, cs, us; uint16_t nl, el, coml, ds, ia; uint32_t ea, lo; };
    struct __attribute__((packed)) LFH { uint32_t sig; uint16_t v, f, cm, mt, md; uint32_t crc, cs, us; uint16_t nl, el; };
    int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) return result;
    off_t fsz = lseek(fd, 0, SEEK_END);
    EOCD eocd{}; bool found = false;
    for (off_t p = fsz - (off_t)sizeof(EOCD); p >= 0 && p > fsz - 65536; p--) {
        lseek(fd, p, SEEK_SET); read(fd, &eocd, sizeof(eocd));
        if (eocd.sig == 0x06054b50) { found = true;break; }
    }
    if (!found) { close(fd);return result; }
    lseek(fd, eocd.co, SEEK_SET);
    for (int i = 0;i < eocd.et;i++) {
        CD cd{}; if (read(fd, &cd, sizeof(cd)) != (int)sizeof(cd)) break; if (cd.sig != 0x02014b50) break;
        std::string en(cd.nl, '\0'); read(fd, &en[0], cd.nl); lseek(fd, cd.el + cd.coml, SEEK_CUR);
        if (en.size() > 3 && en.substr(en.size() - 3) == ".so" &&
            (en.find("lib/arm64") != std::string::npos || en.find("lib/aarch64") != std::string::npos)) {
            LFH lfh{}; off_t saved = lseek(fd, 0, SEEK_CUR);
            lseek(fd, cd.lo, SEEK_SET); read(fd, &lfh, sizeof(lfh));
            uint64_t data_offset = cd.lo + sizeof(lfh) + lfh.nl + lfh.el;
            lseek(fd, saved, SEEK_SET);
            size_t slash = en.rfind('/');
            std::string lib_name = (slash != std::string::npos) ? en.substr(slash + 1) : en;
            if (!lib_name.empty()) result[data_offset] = lib_name;
        }
    }
    close(fd);
    return result;
}

// ═══════════════════════════════════════════════════════
//  dl_iterate_phdr tabanlı modül listesi
//  APK embedded SO'ları da yakalar
// ═══════════════════════════════════════════════════════
struct ModuleListResult {
    std::vector<ModuleInfo> modules;
};

static std::vector<ModuleInfo> enumerate_modules_dl() {
    // Önce APK path'lerini bul, offset map'leri hazırla
    std::set<std::string> apk_paths;
    {
        std::ifstream f("/proc/self/maps");
        std::string line;
        while (std::getline(f, line)) {
            if (line.find(".apk") == std::string::npos) continue;
            size_t pp = line.rfind(' '); if (pp == std::string::npos) continue;
            std::string path = line.substr(pp + 1);
            if (!path.empty() && path[0] == '/' && path.size() > 4 &&
                path.substr(path.size() - 4) == ".apk") apk_paths.insert(path);
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_apk_cache_mutex);
        for (auto& apk : apk_paths) {
            if (!g_apk_offset_cache.count(apk)) {
                g_apk_offset_cache[apk] = build_apk_offset_map(apk);
            }
        }
    }

    struct Ctx {
        std::map<std::string, std::map<uint64_t, std::string>>* cache;
        std::set<std::string>* apk_paths;
        std::vector<ModuleInfo> result;
        std::set<std::string> seen_names;
    };

    std::map<std::string, std::map<uint64_t, std::string>> cache_copy;
    {
        std::lock_guard<std::mutex> lock(g_apk_cache_mutex);
        cache_copy = g_apk_offset_cache;
    }

    Ctx ctx{ &cache_copy, &apk_paths, {}, {} };

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* d) -> int {
        auto* c = (Ctx*)d;
        std::string name = info->dlpi_name ? info->dlpi_name : "";
        if (name.empty()) return 0;
        uint64_t base = (uint64_t)info->dlpi_addr;

        // APK embedded SO mu?
        if (c->apk_paths->count(name)) {
            uint64_t file_off = 0;
            for (int i = 0;i < info->dlpi_phnum;i++)
                if (info->dlpi_phdr[i].p_type == PT_LOAD) { file_off = info->dlpi_phdr[i].p_offset;break; }
            auto& omap = (*c->cache)[name];
            std::string lib_name;
            auto it = omap.find(file_off);
            if (it != omap.end()) lib_name = it->second;
            else {
                for (auto& [off, n] : omap) {
                    uint64_t diff = (off > file_off) ? off - file_off : file_off - off;
                    if (diff < 8192) { lib_name = n;break; }
                }
            }
            if (!lib_name.empty() && !c->seen_names.count(lib_name)) {
                c->seen_names.insert(lib_name);
                std::string lib_path = name + "!/" + lib_name;
                c->result.push_back({ lib_name, lib_path, base });
            }
            return 0;
        }

        // Normal SO
        size_t slash = name.rfind('/');
        std::string short_name = (slash != std::string::npos) ? name.substr(slash + 1) : name;
        if (!short_name.empty() && !c->seen_names.count(short_name)) {
            c->seen_names.insert(short_name);
            c->result.push_back({ short_name, name, base });
        }
        return 0;
        }, &ctx);

    return ctx.result;
}

// ═══════════════════════════════════════════════════════
//  SEMBOL BULMA
// ═══════════════════════════════════════════════════════
static bool find_module(const std::string& lib_name, ModuleInfo& out) {
    void* h = dlopen(lib_name.c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (h) {
        void* sym = dlsym(h, "_init");
        if (!sym) sym = dlsym(h, "_fini");
        if (!sym) sym = dlsym(h, "__cxa_finalize");
        if (sym) {
            Dl_info info{};
            if (dladdr(sym, &info) && info.dli_fbase) {
                out = { lib_name, lib_name, (uint64_t)info.dli_fbase };
                return true;
            }
        }
    }
    auto modules = get_loaded_modules_from_maps();
    for (auto& m : modules) {
        if (m.name == lib_name || m.name.find(lib_name) != std::string::npos) {
            out = m; return true;
        }
    }
    // dl_iterate_phdr ile de ara (APK embedded için)
    auto dl_mods = enumerate_modules_dl();
    for (auto& m : dl_mods) {
        if (m.name == lib_name || m.name.find(lib_name) != std::string::npos) {
            out = m; return true;
        }
    }
    return false;
}

static uint64_t find_symbol_with_dlsym(const std::string& lib_name, const std::string& sym_name) {
    void* h = dlopen(lib_name.c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (!h) h = dlopen(lib_name.c_str(), RTLD_NOW);
    if (h) {
        void* sym = dlsym(h, sym_name.c_str());
        if (sym) { LOGI("dlsym found %s::%s @ %p", lib_name.c_str(), sym_name.c_str(), sym); return (uint64_t)sym; }
    }
    return 0;
}

static uint64_t find_symbol_elf_parse(const ModuleInfo& mod, const std::string& sym_name) {
    std::string elf_path = mod.path; off_t elf_offset = 0;
    size_t excl = mod.path.rfind('!');
    if (excl != std::string::npos) {
        std::string apk = mod.path.substr(0, excl);
        std::string inner = mod.path.substr(excl + 1);
        if (!inner.empty() && inner[0] == '/') inner = inner.substr(1);
        struct __attribute__((packed)) EOCD2 { uint32_t sig; uint16_t d, sd, ed, et; uint32_t cs, co; uint16_t cl; };
        struct __attribute__((packed)) CD2 { uint32_t sig; uint16_t vm, vn, fl, cm, mt, md; uint32_t crc, cs, us; uint16_t nl, el, coml, ds, ia; uint32_t ea, lo; };
        struct __attribute__((packed)) LFH2 { uint32_t sig; uint16_t v, f, cm, mt, md; uint32_t crc, cs, us; uint16_t nl, el; };
        int fd2 = open(apk.c_str(), O_RDONLY);
        if (fd2 >= 0) {
            off_t fsz = lseek(fd2, 0, SEEK_END); EOCD2 eocd{}; bool fe = false;
            for (off_t p = fsz - (off_t)sizeof(EOCD2);p >= 0 && p > fsz - 65536;p--) { lseek(fd2, p, SEEK_SET);read(fd2, &eocd, sizeof(eocd));if (eocd.sig == 0x06054b50) { fe = true;break; } }
            if (fe) {
                lseek(fd2, eocd.co, SEEK_SET);
                for (int i = 0;i < eocd.et;i++) {
                    CD2 cd{}; if (read(fd2, &cd, sizeof(cd)) != (int)sizeof(cd)) break; if (cd.sig != 0x02014b50) break;
                    std::string en(cd.nl, '\0'); read(fd2, &en[0], cd.nl); lseek(fd2, cd.el + cd.coml, SEEK_CUR);
                    if (en == inner && cd.cm == 0) { LFH2 lfh{};lseek(fd2, cd.lo, SEEK_SET);read(fd2, &lfh, sizeof(lfh));elf_offset = cd.lo + sizeof(lfh) + lfh.nl + lfh.el;elf_path = apk;break; }
                }
            }
            close(fd2);
        }
    }
    int fd = open(elf_path.c_str(), O_RDONLY); if (fd < 0) return 0;
    Elf64_Ehdr ehdr{}; lseek(fd, elf_offset, SEEK_SET);
    if (read(fd, &ehdr, sizeof(ehdr)) != (int)sizeof(ehdr) || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) { close(fd);return 0; }
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum); lseek(fd, elf_offset + ehdr.e_shoff, SEEK_SET); read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr));
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum); lseek(fd, elf_offset + ehdr.e_phoff, SEEK_SET); read(fd, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr));
    uint64_t bias = 0; for (auto& ph : phdrs) if (ph.p_type == PT_LOAD) { bias = ph.p_vaddr;break; }
    uint64_t result = 0;
    for (auto& sh : shdrs) {
        if (sh.sh_type != SHT_DYNSYM && sh.sh_type != SHT_SYMTAB) continue;
        if (sh.sh_link >= (uint32_t)ehdr.e_shnum) continue;
        std::vector<Elf64_Sym> syms(sh.sh_size / sizeof(Elf64_Sym)); lseek(fd, elf_offset + sh.sh_offset, SEEK_SET); read(fd, syms.data(), sh.sh_size);
        auto& strsh = shdrs[sh.sh_link]; std::vector<char> strtab(strsh.sh_size + 1, 0); lseek(fd, elf_offset + strsh.sh_offset, SEEK_SET); read(fd, strtab.data(), strsh.sh_size);
        for (auto& sym : syms) {
            if (!sym.st_value || sym.st_name >= strsh.sh_size) continue;
            if (sym_name == &strtab[sym.st_name]) { result = mod.base - bias + sym.st_value;LOGI("ELF found %s @ 0x%lx", sym_name.c_str(), result);break; }
        }
        if (result) break;
    }
    close(fd);
    return result;
}

// ═══════════════════════════════════════════════════════
//  ARM64 TRAMPOLINE + THUNK
// ═══════════════════════════════════════════════════════
static uint64_t make_trampoline(const uint8_t* orig, uint64_t return_addr) {
    void* p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    uint8_t* b = (uint8_t*)p; memcpy(b, orig, 16); b += 16;
    uint32_t ldr = 0x58000051, br = 0xD61F0220;
    memcpy(b, &ldr, 4); b += 4; memcpy(b, &br, 4); b += 4; memcpy(b, &return_addr, 8);
    return (uint64_t)p;
}

struct HookCallCtx {
    int hook_id; uint64_t args[8]; uint64_t trampoline_addr;
    char lib[128]; char symbol[128];
};
extern "C" uint64_t mars_dispatch(HookCallCtx* ctx);

static uint64_t make_thunk(int hook_id, uint64_t trampoline_addr, const char* lib, const char* symbol) {
    uint8_t* page = (uint8_t*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 0;
    HookCallCtx* ctx = (HookCallCtx*)(page + 512);
    ctx->hook_id = hook_id; ctx->trampoline_addr = trampoline_addr;
    strncpy(ctx->lib, lib, 127); strncpy(ctx->symbol, symbol, 127);
    uint64_t ca = (uint64_t)ctx, da = (uint64_t)mars_dispatch;
    std::vector<uint32_t> insns;
    auto mov64 = [&](int r, uint64_t v) {
        insns.push_back(0xD2800000 | ((v & 0xFFFF) << 5) | r);
        insns.push_back(0xF2A00000 | (((v >> 16) & 0xFFFF) << 5) | r);
        insns.push_back(0xF2C00000 | (((v >> 32) & 0xFFFF) << 5) | r);
        insns.push_back(0xF2E00000 | (((v >> 48) & 0xFFFF) << 5) | r);
        };
    insns.push_back(0xA9BF7BFD);
    mov64(9, ca);
    uint32_t ao = offsetof(HookCallCtx, args);
    insns.push_back(0xA9000000 | ((ao / 8 & 0x7F) << 15) | (1 << 10) | (9 << 5) | 0);
    insns.push_back(0xA9000000 | (((ao + 16) / 8 & 0x7F) << 15) | (3 << 10) | (9 << 5) | 2);
    insns.push_back(0xA9000000 | (((ao + 32) / 8 & 0x7F) << 15) | (5 << 10) | (9 << 5) | 4);
    insns.push_back(0xA9000000 | (((ao + 48) / 8 & 0x7F) << 15) | (7 << 10) | (9 << 5) | 6);
    insns.push_back(0xAA0903E0); mov64(10, da);
    insns.push_back(0xD63F0140); insns.push_back(0xA8C17BFD); insns.push_back(0xD65F03C0);
    memcpy(page, insns.data(), insns.size() * 4);
    __builtin___clear_cache((char*)page, (char*)page + insns.size() * 4);
    return (uint64_t)page;
}

extern "C" uint64_t mars_dispatch(HookCallCtx* ctx) {
    LOGI("dispatch hook_id=%d symbol=%s", ctx->hook_id, ctx->symbol);
    IPCMsg before{}; before.type = IPCMsgType::HOOK_BEFORE; before.hook_id = ctx->hook_id;
    for (int i = 0;i < 8;i++) before.args[i] = ctx->args[i];
    strncpy(before.lib, ctx->lib, 127); strncpy(before.symbol, ctx->symbol, 127);
    ipc_client_cb_send(before);
    IPCMsg reply{};
    if (ipc_client_cb_recv(reply, 50))
        if (reply.type == IPCMsgType::SET_ARG) ctx->args[reply.hook_id] = reply.override_val;
    typedef uint64_t(*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    auto fn = (fn_t)ctx->trampoline_addr;
    uint64_t ret = fn(ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3],
        ctx->args[4], ctx->args[5], ctx->args[6], ctx->args[7]);
    IPCMsg after{}; after.type = IPCMsgType::HOOK_AFTER; after.hook_id = ctx->hook_id; after.ret_val = ret;
    for (int i = 0;i < 8;i++) after.args[i] = ctx->args[i];
    strncpy(after.lib, ctx->lib, 127); strncpy(after.symbol, ctx->symbol, 127);
    ipc_client_cb_send(after);
    IPCMsg rr{};
    if (ipc_client_cb_recv(rr, 50)) if (rr.type == IPCMsgType::SET_RET) ret = rr.override_val;
    return ret;
}

static bool install_hook(int hook_id, const std::string& lib, const std::string& symbol, uint64_t target_addr = 0) {
    uint64_t target = target_addr;
    if (!target) {
        target = find_symbol_with_dlsym(lib, symbol);
        if (!target) { ModuleInfo mod;if (find_module(lib, mod)) target = find_symbol_elf_parse(mod, symbol); }
        if (!target) { LOGI("symbol not found: %s::%s", lib.c_str(), symbol.c_str());return false; }
    }
    LOGI("install_hook: %s::%s @ 0x%lx", lib.c_str(), symbol.c_str(), target);
    InternalHook hook; hook.hook_id = hook_id; hook.target_addr = target;
    strncpy(hook.lib, lib.c_str(), 127); strncpy(hook.symbol, symbol.c_str(), 127);
    memcpy(hook.orig_bytes, (void*)target, 16);
    hook.trampoline_addr = make_trampoline(hook.orig_bytes, target + 16);
    if (!hook.trampoline_addr) return false;
    uint64_t thunk = make_thunk(hook_id, hook.trampoline_addr, lib.c_str(), symbol.c_str());
    if (!thunk) return false;
    uintptr_t page = target & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) { LOGI("mprotect failed errno=%d", errno);return false; }
    uint8_t patch[16]; uint32_t ldr = 0x58000051, br = 0xD61F0220;
    memcpy(patch + 0, &ldr, 4); memcpy(patch + 4, &br, 4); memcpy(patch + 8, &thunk, 8);
    memcpy((void*)target, patch, 16);
    __builtin___clear_cache((char*)target, (char*)(target + 16));
    mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);
    LOGI("patch done @ 0x%lx", target);
    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    g_hooks.push_back(hook);
    return true;
}

// ═══════════════════════════════════════════════════════
//  LIB WATCHER THREAD — v7 (g_apk_offset_cache kullanır)
// ═══════════════════════════════════════════════════════
static void lib_watcher_thread() {
    std::set<std::string> notified_names;

    while (true) {
        // APK path'lerini bul
        std::set<std::string> apk_paths;
        {
            std::ifstream f("/proc/self/maps");
            std::string line;
            while (std::getline(f, line)) {
                if (line.find(".apk") == std::string::npos) continue;
                size_t pp = line.rfind(' '); if (pp == std::string::npos) continue;
                std::string path = line.substr(pp + 1);
                if (!path.empty() && path[0] == '/' && path.size() > 4 &&
                    path.substr(path.size() - 4) == ".apk") apk_paths.insert(path);
            }
        }

        // APK offset map'lerini global cache'e ekle
        {
            std::lock_guard<std::mutex> lock(g_apk_cache_mutex);
            for (auto& apk : apk_paths) {
                if (!g_apk_offset_cache.count(apk)) {
                    g_apk_offset_cache[apk] = build_apk_offset_map(apk);
                }
            }
        }

        // dl_iterate_phdr ile enumerate
        auto mods = enumerate_modules_dl();
        for (auto& mod : mods) {
            if (notified_names.count(mod.name)) continue;
            notified_names.insert(mod.name);
            LOGI("lib_loaded: %s @ 0x%lx", mod.name.c_str(), mod.base);
            IPCMsg msg{};
            msg.type = IPCMsgType::LIB_LOADED_RESP;
            msg.hook_id = 1; msg.target_addr = mod.base;
            strncpy(msg.lib, mod.name.c_str(), 127);
            size_t plen = std::min(mod.path.size(), (size_t)IPC_PAYLOAD_SIZE - 1);
            memcpy(msg.payload, mod.path.c_str(), plen);
            msg.payload[plen] = '\0'; msg.payload_size = (uint32_t)plen;
            ipc_client_cb_send(msg);
        }

        usleep(200000);
    }
}

// ═══════════════════════════════════════════════════════
//  IPC COMMAND LOOP — v7
//  MODULE_LIST_REQ: dl_iterate_phdr tabanlı
// ═══════════════════════════════════════════════════════
static void command_loop() {
    while (true) {
        IPCMsg msg{};
        if (!ipc_client_cmd_recv(msg, 5000)) continue;

        if (msg.type == IPCMsgType::HOOK_INSTALL) {
            LOGI("hook_install: %s::%s id=%d addr=0x%lx", msg.lib, msg.symbol, msg.hook_id, msg.target_addr);
            bool ok = install_hook(msg.hook_id, msg.lib, msg.symbol, msg.target_addr);
            LOGI("hook_install: %s", ok ? "ok" : "failed");
            IPCMsg reply{}; reply.type = ok ? IPCMsgType::READY : IPCMsgType::HOOK_REMOVE; reply.hook_id = msg.hook_id;
            ipc_client_cmd_send(reply);
        }
        else if (msg.type == IPCMsgType::FIND_SYMBOL_REQ) {
            LOGI("find_symbol_req: %s::%s", msg.lib, msg.symbol);
            uint64_t addr = find_symbol_with_dlsym(msg.lib, msg.symbol);
            if (!addr) { ModuleInfo mod; if (find_module(msg.lib, mod)) addr = find_symbol_elf_parse(mod, msg.symbol); }
            IPCMsg reply{}; reply.type = IPCMsgType::FIND_SYMBOL_RESP; reply.hook_id = msg.hook_id; reply.target_addr = addr;
            strncpy(reply.lib, msg.lib, 127); strncpy(reply.symbol, msg.symbol, 127);
            ipc_client_cmd_send(reply);
            LOGI("find_symbol_resp: 0x%lx", addr);
        }
        else if (msg.type == IPCMsgType::MODULE_LIST_REQ) {
            // ── dl_iterate_phdr tabanlı — APK embedded SO'lar dahil ──
            auto mods = enumerate_modules_dl();
            std::ostringstream json; json << "[";
            for (size_t i = 0;i < mods.size();i++) {
                if (i) json << ",";
                json << "{\"name\":\"" << mods[i].name << "\","
                    << "\"path\":\"" << mods[i].path << "\","
                    << "\"base\":\"0x" << std::hex << mods[i].base << "\"}";
            }
            json << "]";
            std::string js = json.str();
            IPCMsg reply{}; reply.type = IPCMsgType::MODULE_LIST_RESP;
            reply.payload_size = (uint32_t)std::min(js.size(), (size_t)IPC_PAYLOAD_SIZE - 1);
            memcpy(reply.payload, js.c_str(), reply.payload_size);
            reply.payload[reply.payload_size] = '\0';
            ipc_client_cmd_send(reply);
            LOGI("module_list_resp: %zu modules", mods.size());
        }
    }
}

// ═══════════════════════════════════════════════════════
//  SO ENTRY POINT
// ═══════════════════════════════════════════════════════
__attribute__((constructor))
static void mars_hook_init() {
    LOGI("init started v7");
    if (!ipc_client_connect(IPC_CMD_PATH, IPC_CB_PATH)) { LOGI("IPC connect failed"); return; }
    LOGI("IPC connected!");
    IPCMsg ready{}; ready.type = IPCMsgType::READY;
    ipc_client_cb_send(ready);
    std::thread(lib_watcher_thread).detach();
    std::thread(command_loop).detach();
}

__attribute__((destructor))
static void mars_hook_fini() { ipc_client_disconnect(); }