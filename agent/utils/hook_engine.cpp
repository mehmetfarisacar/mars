#include "hook_engine.h"
#include "../commands/command.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <signal.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <mutex>
#include <thread>
#include <atomic>

extern void js_dispatch_hook(int hook_id, HookContext& hctx, bool is_before);

// ═══════════════════════════════════════════════════════
//  GLOBALS
// ═══════════════════════════════════════════════════════
static std::vector<HookEntry> g_hooks;
static std::mutex              g_hooks_mutex;
static int                     g_next_hook_id = 0;

// ─── Breakpoint manager thread ───
static std::atomic<bool>  g_bp_running{ false };
static std::thread        g_bp_thread;

// BRK #0 instruction (ARM64 software breakpoint)
static const uint32_t BRK0 = 0xD4200000;

// Return breakpoint kaydı
struct RetBreakpoint {
    int      hook_id;
    int      tid;          // hedef thread
    uint64_t bp_addr;      // return address
    uint32_t orig_insn;    // orijinal instruction
    HookContext hctx;      // before'dan taşınan context
};
static std::vector<RetBreakpoint> g_ret_bps;
static std::mutex                  g_ret_bps_mutex;

// ═══════════════════════════════════════════════════════
//  MEMORY R/W
// ═══════════════════════════════════════════════════════
static bool remote_read(int pid, uint64_t addr, void* buf, size_t size) {
    struct iovec local = { buf, size };
    struct iovec remote = { reinterpret_cast<void*>(addr), size };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)size;
}

static bool remote_write_mem_fd(int pid, uint64_t addr,
    const void* buf, size_t size) {
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = pwrite64(fd, buf, size, (off64_t)addr);
    close(fd);
    return n == (ssize_t)size;
}

static bool ptrace_write(int pid, uint64_t addr,
    const void* buf, size_t size) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) return false;
    int status = 0;
    waitpid(pid, &status, 0);
    bool ok = remote_write_mem_fd(pid, addr, buf, size);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return ok;
}

// ═══════════════════════════════════════════════════════
//  ARM64 REGISTER STRUCT
// ═══════════════════════════════════════════════════════
struct Arm64Regs {
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
};

static bool get_regs(int tid, Arm64Regs& regs) {
    struct iovec iov = { &regs, sizeof(regs) };
    return ptrace(PTRACE_GETREGSET, tid, (void*)1, &iov) == 0;
}

static bool set_regs(int tid, Arm64Regs& regs) {
    struct iovec iov = { &regs, sizeof(regs) };
    return ptrace(PTRACE_SETREGSET, tid, (void*)1, &iov) == 0;
}

// ═══════════════════════════════════════════════════════
//  THREAD LIST
// ═══════════════════════════════════════════════════════
static std::vector<int> get_threads(int pid) {
    std::vector<int> tids;
    std::string path = "/proc/" + std::to_string(pid) + "/task";
    auto* dir = opendir(path.c_str());
    if (!dir) return tids;
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        tids.push_back(atoi(entry->d_name));
    }
    closedir(dir);
    return tids;
}

// ═══════════════════════════════════════════════════════
//  ELF SYMBOL FINDER
// ═══════════════════════════════════════════════════════
struct LibInfo { uint64_t base; std::string path; };

static LibInfo get_lib_info(int pid, const std::string& lib_name) {
    LibInfo info{ 0, "" };
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    if (!f.is_open()) return info;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(lib_name) == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos &&
            line.find("r--p") == std::string::npos) continue;
        uint64_t start = 0;
        char path[512] = { 0 };
        sscanf(line.c_str(), "%lx-%*x %*s %*s %*s %*s %511s", &start, path);
        info.base = start;
        info.path = path;
        return info;
    }
    return info;
}

static uint64_t elf_find_symbol_offset(const std::string& elf_path,
    const std::string& symbol_name) {
    int fd = open(elf_path.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd); return 0;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr));

    Elf64_Shdr& shstr = shdrs[ehdr.e_shstrndx];
    std::vector<char> shstrtab(shstr.sh_size);
    lseek(fd, shstr.sh_offset, SEEK_SET);
    read(fd, shstrtab.data(), shstr.sh_size);

    for (auto& sh : shdrs) {
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
        if (sh.sh_link >= ehdr.e_shnum) continue;

        uint64_t sym_count = sh.sh_size / sizeof(Elf64_Sym);
        std::vector<Elf64_Sym> syms(sym_count);
        lseek(fd, sh.sh_offset, SEEK_SET);
        read(fd, syms.data(), sh.sh_size);

        lseek(fd, 0, SEEK_END);
        size_t str_size = (size_t)(lseek(fd, 0, SEEK_CUR) -
            (off_t)shdrs[sh.sh_link].sh_offset);
        if (str_size > 4 * 1024 * 1024) str_size = 4 * 1024 * 1024;
        std::vector<char> strtab(str_size + 1, 0);
        lseek(fd, shdrs[sh.sh_link].sh_offset, SEEK_SET);
        read(fd, strtab.data(), str_size);

        for (auto& sym : syms) {
            if (sym.st_value == 0 || sym.st_name >= str_size) continue;
            if (symbol_name == &strtab[sym.st_name]) {
                close(fd);
                // IFUNC sembolü ise resolved adresi döndür
                if (ELF64_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
                    return (uint64_t)-1; // caller'a IFUNC olduğunu bildir
                }
                return sym.st_value;
            }
        }
    }
    close(fd);
    return 0;
}

static uint64_t elf_load_bias(const std::string& elf_path) {
    int fd = open(elf_path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return 0; }
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr));
    close(fd);
    for (auto& ph : phdrs)
        if (ph.p_type == PT_LOAD) return ph.p_vaddr;
    return 0;
}

uint64_t find_symbol_addr(int pid, const std::string& lib_name,
    const std::string& symbol_name) {
    LibInfo info = get_lib_info(pid, lib_name);
    if (info.base == 0 || info.path.empty()) return 0;
    if (symbol_name.empty()) return info.base;
    uint64_t offset = elf_find_symbol_offset(info.path, symbol_name);
    if (offset == 0) return 0;

    // IFUNC sembolü (-1 dönerse) — agent dlsym + rebase ile resolve et
    if (offset == (uint64_t)-1) {
        // Agent kendi process'inde dlsym yapıyor
        void* handle = dlopen(info.path.c_str(), RTLD_NOLOAD | RTLD_NOW);
        if (!handle) handle = dlopen(lib_name.c_str(), RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "[find_symbol] IFUNC dlopen failed for %s\n", lib_name.c_str());
            return 0;
        }
        void* sym = dlsym(handle, symbol_name.c_str());
        if (!sym) return 0;
        uint64_t agent_sym_addr = (uint64_t)sym;

        // Agent'ın libc base'ini bul
        uint64_t agent_lib_base = 0;
        std::ifstream agent_maps("/proc/self/maps");
        std::string mline;
        while (std::getline(agent_maps, mline)) {
            if (mline.find(info.path) == std::string::npos &&
                mline.find(lib_name) == std::string::npos) continue;
            if (mline.find("r-xp") == std::string::npos) continue;
            sscanf(mline.c_str(), "%lx", &agent_lib_base);
            break;
        }

        if (agent_lib_base == 0) {
            fprintf(stderr, "[find_symbol] IFUNC: agent lib base not found\n");
            return 0;
        }

        // offset = agent_sym_addr - agent_lib_base
        // target_addr = target_lib_base + offset
        uint64_t sym_offset = agent_sym_addr - agent_lib_base;
        uint64_t target_addr = info.base + sym_offset;
        fprintf(stderr, "[find_symbol] IFUNC resolved: %s agent=0x%lx offset=0x%lx target=0x%lx\n",
            symbol_name.c_str(), agent_sym_addr, sym_offset, target_addr);
        return target_addr;
    }

    uint64_t bias = elf_load_bias(info.path);
    return info.base - bias + offset;
}

// ═══════════════════════════════════════════════════════
//  BREAKPOINT MANAGER THREAD
//
//  Tüm threadleri izler. SIGTRAP gelince:
//  1. Hangi breakpoint tetiklendi bul
//  2. after JS callback çağır
//  3. setRet varsa x0 yaz
//  4. Orijinal instruction'ı geri yaz
//  5. Thread'i devam ettir
// ═══════════════════════════════════════════════════════
static void bp_manager_thread() {
    while (g_bp_running.load()) {
        int pid = get_attached_pid();
        if (pid <= 0) { usleep(100000); continue; }

        // Bekleyen return breakpoint var mı?
        {
            std::lock_guard<std::mutex> lock(g_ret_bps_mutex);
            if (g_ret_bps.empty()) { usleep(10000); continue; }
        }

        // Tüm thread'leri waitpid ile izle
        auto tids = get_threads(pid);
        for (int tid : tids) {
            int status = 0;
            int ret = waitpid(tid, &status, WNOHANG | __WALL);
            if (ret <= 0) continue;
            if (!WIFSTOPPED(status)) continue;
            if (WSTOPSIG(status) != SIGTRAP) {
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                continue;
            }

            // SIGTRAP geldi — hangi breakpoint?
            Arm64Regs regs{};
            if (!get_regs(tid, regs)) {
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                continue;
            }

            // BRK #0 sonrası PC bir instruction ileri gitmez — PC = bp_addr
            uint64_t trap_pc = regs.pc;

            RetBreakpoint* found_bp = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_ret_bps_mutex);
                for (auto& bp : g_ret_bps) {
                    if (bp.tid == tid && bp.bp_addr == trap_pc) {
                        found_bp = &bp;
                        break;
                    }
                }
            }

            if (!found_bp) {
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                continue;
            }

            // Return value oku
            HookContext hctx = found_bp->hctx;
            hctx.ret_val = regs.regs[0];

            // AFTER callback çağır
            js_dispatch_hook(hctx.hook_id, hctx, false);

            // setRet varsa x0 yaz
            if (hctx.ret_modified) {
                regs.regs[0] = hctx.ret_new_val;
                set_regs(tid, regs);
                send_async("[setRet] hook_id=" + std::to_string(hctx.hook_id) +
                    " x0=" + std::to_string(hctx.ret_new_val));
            }

            // Orijinal instruction'ı geri yaz
            remote_write_mem_fd(tid, found_bp->bp_addr,
                &found_bp->orig_insn, 4);

            // BP kaydını sil
            {
                std::lock_guard<std::mutex> lock(g_ret_bps_mutex);
                for (auto it = g_ret_bps.begin(); it != g_ret_bps.end(); ++it) {
                    if (it->tid == tid && it->bp_addr == trap_pc) {
                        g_ret_bps.erase(it);
                        break;
                    }
                }
            }

            // Thread devam et
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        }

        usleep(1000); // 1ms
    }
}

// ═══════════════════════════════════════════════════════
//  BEFORE HOOK + RET BREAKPOINT KOYMA
//
//  Hook tetiklenince (trampoline'den önce):
//  1. ptrace attach
//  2. Register oku → HookContext
//  3. JS before callback çağır
//  4. setArg varsa register'a yaz
//  5. LR (x30) adresine BRK #0 yaz → return breakpoint
//  6. BP manager'a kaydet
//  7. ptrace detach → thread kaldığı yerden devam eder
//
//  Ama trampoline'den bunu tetiklemek için:
//  Trampoline başına özel bir stub yazamıyoruz (farklı process).
//
//  ÇÖZÜM: ptrace PTRACE_SEIZE + PTRACE_INTERRUPT kullanarak
//  hook adresine yazılan BRK #0 sonrası SIGTRAP yakalanır.
//  Hem before hem after için BRK tabanlı yaklaşım:
//
//  hook_install:
//    target_addr'e BRK #0 yaz (16 byte patch yerine 4 byte)
//    Thread SIGTRAP ürettiğinde:
//      - before context için: LR oku, LR adresine BRK yaz
//      - before callback çağır, setArg uygula
//      - Orijinal instruction'ı çalıştır (single step)
//      - Thread devam et
//    LR adresinde SIGTRAP:
//      - after callback çağır, setRet uygula
//      - Orijinal instruction geri yaz
//      - Thread devam et
// ═══════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
//  TRAMPOLINE (basit — orijinal bytes + geri dön)
// ═══════════════════════════════════════════════════════
static uint64_t create_trampoline(const uint8_t* orig_bytes,
    uint64_t return_addr) {
    void* page = mmap(nullptr, 4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 0;

    uint8_t* p = (uint8_t*)page;
    memcpy(p, orig_bytes, 8); p += 8;

    // LDR X17, #8
    uint32_t ldr = 0x58000051;
    memcpy(p, &ldr, 4); p += 4;
    // BR X17
    uint32_t br = 0xD61F0220;
    memcpy(p, &br, 4); p += 4;
    // return_addr
    memcpy(p, &return_addr, 8);

    return (uint64_t)page;
}

// ═══════════════════════════════════════════════════════
//  HOOK INSTALL
// ═══════════════════════════════════════════════════════
int hook_install_brk(int pid, const std::string& lib,
    const std::string& symbol, uint64_t target_addr) {
    if (target_addr == 0) return -1;

    HookEntry entry;
    entry.hook_id = g_next_hook_id++;
    entry.target_addr = target_addr;
    entry.lib = lib;
    entry.symbol = symbol;
    entry.override_flag_addr = 0;
    entry.override_val_addr = 0;

    // Orijinal instruction oku
    if (!remote_read(pid, target_addr, entry.original_bytes, 4))
        return -1;
    // 8 byte tampon (restore için)
    remote_read(pid, target_addr + 4, entry.original_bytes + 4, 4);

    entry.trampoline_addr = 0;

    // BRK #0 yaz
    if (!ptrace_write(pid, target_addr, &BRK0, 4))
        return -1;

    // BP manager başlat
    if (!g_bp_running.load()) {
        g_bp_running = true;
        g_bp_thread = std::thread([pid]() {
            // tüm thread'leri PTRACE_SEIZE et
            auto tids = get_threads(pid);
            for (int tid : tids) {
                ptrace(PTRACE_SEIZE, tid, nullptr, (void*)PTRACE_O_TRACECLONE);
            }

            while (g_bp_running.load()) {
                int status = 0;
                int tid = waitpid(-1, &status, WNOHANG | __WALL);
                if (tid <= 0) { usleep(1000); continue; }

                if (!WIFSTOPPED(status)) {
                    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                    continue;
                }

                int sig = WSTOPSIG(status);
                if (sig != SIGTRAP) {
                    ptrace(PTRACE_CONT, tid, nullptr, (void*)(intptr_t)sig);
                    continue;
                }

                Arm64Regs regs{};
                if (!get_regs(tid, regs)) {
                    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                    continue;
                }

                uint64_t trap_pc = regs.pc; // BRK'da PC = BRK adresi

                // Bu bir hook noktası mı?
                HookEntry* hook_entry = nullptr;
                {
                    std::lock_guard<std::mutex> lk(g_hooks_mutex);
                    for (auto& e : g_hooks) {
                        if (e.target_addr == trap_pc) {
                            hook_entry = &e;
                            break;
                        }
                    }
                }

                if (hook_entry) {
                    // ─── BEFORE ───
                    HookContext hctx;
                    hctx.hook_id = hook_entry->hook_id;
                    hctx.lib = hook_entry->lib;
                    hctx.symbol = hook_entry->symbol;
                    hctx.target_addr = hook_entry->target_addr;
                    for (int i = 0; i < 8; i++)
                        hctx.args[i] = regs.regs[i];

                    js_dispatch_hook(hook_entry->hook_id, hctx, true);

                    // setArg uygula
                    for (int i = 0; i < 8; i++) {
                        if (hctx.arg_modified[i])
                            regs.regs[i] = hctx.arg_new_val[i];
                    }

                    // LR (x30) adresine BRK #0 yaz — return breakpoint
                    uint64_t lr = regs.regs[30];
                    uint32_t orig_insn = 0;
                    remote_read(pid, lr, &orig_insn, 4);
                    remote_write_mem_fd(pid, lr, &BRK0, 4);

                    // Return BP kaydet
                    {
                        std::lock_guard<std::mutex> lk(g_ret_bps_mutex);
                        RetBreakpoint bp;
                        bp.hook_id = hook_entry->hook_id;
                        bp.tid = tid;
                        bp.bp_addr = lr;
                        bp.orig_insn = orig_insn;
                        bp.hctx = hctx;
                        g_ret_bps.push_back(bp);
                    }

                    // Orijinal instruction'ı geri yaz + single step
                    remote_write_mem_fd(pid, trap_pc, hook_entry->original_bytes, 4);
                    set_regs(tid, regs);
                    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);

                    // Single step tamamlanınca BRK'yı tekrar yaz
                    int ss_status = 0;
                    waitpid(tid, &ss_status, __WALL);
                    remote_write_mem_fd(pid, trap_pc, &BRK0, 4);

                    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                    continue;
                }

                // Bu bir return breakpoint mi?
                RetBreakpoint* ret_bp = nullptr;
                {
                    std::lock_guard<std::mutex> lk(g_ret_bps_mutex);
                    for (auto& bp : g_ret_bps) {
                        if (bp.bp_addr == trap_pc) {
                            ret_bp = &bp;
                            break;
                        }
                    }
                }

                if (ret_bp) {
                    // ─── AFTER ───
                    HookContext hctx = ret_bp->hctx;
                    hctx.ret_val = regs.regs[0];

                    js_dispatch_hook(hctx.hook_id, hctx, false);

                    // setRet uygula
                    if (hctx.ret_modified) {
                        regs.regs[0] = hctx.ret_new_val;
                        set_regs(tid, regs);
                        send_async("[setRet] " + hctx.symbol +
                            " x0=" + std::to_string(hctx.ret_new_val));
                    }

                    // Orijinal instruction geri yaz
                    remote_write_mem_fd(pid, ret_bp->bp_addr,
                        &ret_bp->orig_insn, 4);

                    // BP kaydını sil
                    {
                        std::lock_guard<std::mutex> lk(g_ret_bps_mutex);
                        for (auto it = g_ret_bps.begin();
                            it != g_ret_bps.end(); ++it) {
                            if (it->bp_addr == trap_pc) {
                                g_ret_bps.erase(it);
                                break;
                            }
                        }
                    }

                    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                    continue;
                }

                // Bilinmeyen SIGTRAP — devam et
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            }
            });
        g_bp_thread.detach();
    }

    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    g_hooks.push_back(entry);
    return entry.hook_id;
}

// ═══════════════════════════════════════════════════════
//  PUBLIC hook_install — BRK tabanlı kullan
// ═══════════════════════════════════════════════════════
bool hook_set_ret(int, uint64_t) { return true; } // artık BP manager handle ediyor
bool hook_clear_ret(int) { return true; }

// ═══════════════════════════════════════════════════════
//  HOOK REMOVE
// ═══════════════════════════════════════════════════════
bool hook_remove(int hook_id) {
    int pid = get_attached_pid();
    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
        if (it->hook_id != hook_id) continue;
        if (ptrace_write(pid, it->target_addr, it->original_bytes, 4)) {
            // restored
        }
        if (it->trampoline_addr)
            munmap((void*)it->trampoline_addr, 4096);
        g_hooks.erase(it);
        return true;
    }
    return false;
}

std::vector<HookEntry> hook_list_all() {
    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    return g_hooks;
}

HookEntry* hook_find(int hook_id) {
    for (auto& e : g_hooks)
        if (e.hook_id == hook_id) return &e;
    return nullptr;
}

// hook_install = BRK tabanlı
int hook_install(int pid, const std::string& lib,
    const std::string& symbol, uint64_t target_addr) {
    return hook_install_brk(pid, lib, symbol, target_addr);
}
