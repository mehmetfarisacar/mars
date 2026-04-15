#include "injector.h"
#include "../commands/command.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <vector>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>
#include <cstdio>

static void ilog(const std::string& msg) {
    fprintf(stderr, "%s\n", msg.c_str());
    fflush(stderr);
    send_async(msg);
}
#include <sys/stat.h>

// ═══════════════════════════════════════════════════════
//  ARM64 REGISTER STRUCT
// ═══════════════════════════════════════════════════════
struct Arm64Regs {
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
};

static bool get_regs(int tid, Arm64Regs& r) {
    struct iovec iov = { &r, sizeof(r) };
    return ptrace(PTRACE_GETREGSET, tid, (void*)1, &iov) == 0;
}
static bool set_regs(int tid, Arm64Regs& r) {
    struct iovec iov = { &r, sizeof(r) };
    return ptrace(PTRACE_SETREGSET, tid, (void*)1, &iov) == 0;
}

// ═══════════════════════════════════════════════════════
//  MEMORY R/W
// ═══════════════════════════════════════════════════════
static bool mem_read(int pid, uint64_t addr, void* buf, size_t size) {
    struct iovec li = { buf, size };
    struct iovec ri = { (void*)addr, size };
    return process_vm_readv(pid, &li, 1, &ri, 1, 0) == (ssize_t)size;
}

static bool mem_write(int pid, uint64_t addr, const void* buf, size_t size) {
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) return false;
    bool ok = pwrite64(fd, buf, size, addr) == (ssize_t)size;
    close(fd);
    return ok;
}

static std::string hex(uint64_t v) {
    std::ostringstream o; o << std::hex << v; return o.str();
}

// ═══════════════════════════════════════════════════════
//  MAIN THREAD ID
// ═══════════════════════════════════════════════════════
static int get_main_tid(int pid) {
    // main thread = pid'nin kendisi
    // /proc/pid/task/pid her zaman var
    std::string path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(pid);
    struct stat st {};
    if (stat(path.c_str(), &st) == 0) return pid;

    // fallback: task dizinini tara
    std::string task_path = "/proc/" + std::to_string(pid) + "/task";
    auto* dir = opendir(task_path.c_str());
    if (!dir) return pid; // en kötü ihtimal pid'i döndür
    int min_tid = pid;
    struct dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        int t = atoi(de->d_name);
        if (t > 0 && t < min_tid) min_tid = t;
    }
    closedir(dir);
    return min_tid;
}

// ═══════════════════════════════════════════════════════
//  WAITPID HELPER — timeout ile
// ═══════════════════════════════════════════════════════
static bool wait_stopped(int tid, int timeout_ms = 3000) {
    int status = 0;
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        int r = waitpid(tid, &status, WNOHANG | __WALL);
        if (r == tid && WIFSTOPPED(status)) return true;
        if (r < 0) return false;
        usleep(5000);
        elapsed += 5;
    }
    return false;
}

// ═══════════════════════════════════════════════════════
//  SYSCALL INJECTION — hedef process'te syscall çalıştır
//  Döner: syscall sonucu (x0)
// ═══════════════════════════════════════════════════════
static uint64_t do_syscall(int pid, int tid,
    uint64_t nr,
    uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0,
    uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0) {
    // Mevcut register'ları kaydet
    Arm64Regs orig{};
    if (!get_regs(tid, orig)) {
        ilog("[inject] get_regs failed");
        return (uint64_t)-1;
    }

    // Mevcut PC'deki instruction'ı kaydet
    uint32_t orig_insn = 0;
    if (!mem_read(pid, orig.pc, &orig_insn, 4)) {
        ilog("[inject] mem_read orig_insn failed @ 0x" + hex(orig.pc));
        return (uint64_t)-1;
    }

    // SVC #0 yaz
    uint32_t svc = 0xD4000001;
    if (!mem_write(pid, orig.pc, &svc, 4)) {
        ilog("[inject] mem_write SVC failed");
        return (uint64_t)-1;
    }

    // Syscall register'larını ayarla
    Arm64Regs sc_regs = orig;
    sc_regs.regs[8] = nr;
    sc_regs.regs[0] = a0;
    sc_regs.regs[1] = a1;
    sc_regs.regs[2] = a2;
    sc_regs.regs[3] = a3;
    sc_regs.regs[4] = a4;
    sc_regs.regs[5] = a5;
    set_regs(tid, sc_regs);

    // PTRACE_SYSCALL — syscall entry'de dur
    ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    if (!wait_stopped(tid)) {
        ilog("[inject] wait syscall entry failed");
        mem_write(pid, orig.pc, &orig_insn, 4);
        set_regs(tid, orig);
        return (uint64_t)-1;
    }

    // PTRACE_SYSCALL — syscall exit'te dur
    ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    if (!wait_stopped(tid)) {
        ilog("[inject] wait syscall exit failed");
        mem_write(pid, orig.pc, &orig_insn, 4);
        set_regs(tid, orig);
        return (uint64_t)-1;
    }

    // Sonucu oku
    Arm64Regs res{};
    get_regs(tid, res);
    uint64_t ret = res.regs[0];

    // Restore
    mem_write(pid, orig.pc, &orig_insn, 4);
    set_regs(tid, orig);

    return ret;
}

// ═══════════════════════════════════════════════════════
//  REMOTE FUNCTION CALL — BRK tabanlı
//  func_addr'deki fonksiyonu arg0, arg1 ile çağır
// ═══════════════════════════════════════════════════════
static uint64_t remote_call(int pid, int tid,
    uint64_t func_addr,
    uint64_t a0, uint64_t a1,
    uint64_t scratch_page) {
    Arm64Regs orig{};
    if (!get_regs(tid, orig)) return 0;

    // Scratch page'e shellcode yaz:
    // MOV X0, a0 (4 instruction max)
    // MOV X1, a1
    // LDR X2, #offset   → func_addr
    // BLR X2
    // BRK #0
    // <func_addr 8 byte>

    uint8_t code[64] = {};
    uint8_t* p = code;

    // MOVZ/MOVK helper
    auto emit_mov = [&](int reg, uint64_t val) {
        uint32_t movz = 0xD2800000 | ((val & 0xFFFF) << 5) | reg;
        memcpy(p, &movz, 4); p += 4;
        if (val >> 16) {
            uint32_t movk = 0xF2A00000 | (((val >> 16) & 0xFFFF) << 5) | reg;
            memcpy(p, &movk, 4); p += 4;
        }
        if (val >> 32) {
            uint32_t movk = 0xF2C00000 | (((val >> 32) & 0xFFFF) << 5) | reg;
            memcpy(p, &movk, 4); p += 4;
        }
        if (val >> 48) {
            uint32_t movk = 0xF2E00000 | (((val >> 48) & 0xFFFF) << 5) | reg;
            memcpy(p, &movk, 4); p += 4;
        }
        };

    emit_mov(0, a0);
    emit_mov(1, a1);

    // LDR X2, #offset — func_addr'ı sonuna koy
    // Şu an p, code'dan kaç byte ileride?
    int cur_off = (int)(p - code);
    // func_addr slot = offset 56 (8-aligned, p'den sonra)
    // LDR X2, imm19 — imm19 = (slot_addr - PC) / 4
    // PC = scratch_page + cur_off
    // slot = scratch_page + 56
    int slot_off = 56;
    int ldr_off = slot_off - cur_off; // byte offset from LDR instruction
    int imm19 = ldr_off / 4;
    uint32_t ldr_x2 = 0x58000002 | ((imm19 & 0x7FFFF) << 5);
    memcpy(p, &ldr_x2, 4); p += 4;

    // BLR X2
    uint32_t blr = 0xD63F0040;
    memcpy(p, &blr, 4); p += 4;

    // BRK #0
    uint32_t brk = 0xD4200000;
    memcpy(p, &brk, 4); p += 4;

    // Pad to slot 56
    while ((p - code) < slot_off) {
        uint32_t nop = 0xD503201F;
        memcpy(p, &nop, 4); p += 4;
    }

    // func_addr @ offset 56
    memcpy(p, &func_addr, 8);

    // Shellcode'u yaz
    mem_write(pid, scratch_page, code, 64);

    // PC → shellcode, LR → BRK (sonsuz döngüyü önle)
    Arm64Regs run = orig;
    run.pc = scratch_page;
    run.regs[30] = scratch_page + (int)(p - code) - 12; // BRK adresi
    set_regs(tid, run);

    // Çalıştır — BRK'de duracak
    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    if (!wait_stopped(tid, 5000)) {
        ilog("[inject] remote_call wait failed");
        set_regs(tid, orig);
        return 0;
    }

    // Return value
    Arm64Regs res{};
    get_regs(tid, res);
    uint64_t ret = res.regs[0];

    // Restore
    set_regs(tid, orig);
    return ret;
}

// ═══════════════════════════════════════════════════════
//  REMOTE DLOPEN ADDR
// ═══════════════════════════════════════════════════════
// ELF'ten sembol offsetini bul
static uint64_t elf_sym_offset(const std::string& path, const std::string& sym_name) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr{};
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd); return 0;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr));

    for (auto& sh : shdrs) {
        if (sh.sh_type != SHT_DYNSYM && sh.sh_type != SHT_SYMTAB) continue;
        if (sh.sh_link >= ehdr.e_shnum) continue;

        std::vector<Elf64_Sym> syms(sh.sh_size / sizeof(Elf64_Sym));
        lseek(fd, sh.sh_offset, SEEK_SET);
        read(fd, syms.data(), sh.sh_size);

        lseek(fd, 0, SEEK_END);
        size_t strsz = (size_t)(lseek(fd, 0, SEEK_CUR) - (off_t)shdrs[sh.sh_link].sh_offset);
        if (strsz > 4 * 1024 * 1024) strsz = 4 * 1024 * 1024;
        std::vector<char> strtab(strsz + 1, 0);
        lseek(fd, shdrs[sh.sh_link].sh_offset, SEEK_SET);
        read(fd, strtab.data(), strsz);

        for (auto& sym : syms) {
            if (!sym.st_value || sym.st_name >= strsz) continue;
            if (sym_name == &strtab[sym.st_name]) {
                close(fd);
                return sym.st_value;
            }
        }
    }
    close(fd);
    return 0;
}

// LOAD bias
static uint64_t elf_bias(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    Elf64_Ehdr ehdr{};
    read(fd, &ehdr, sizeof(ehdr));
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr));
    close(fd);
    for (auto& ph : phdrs)
        if (ph.p_type == PT_LOAD) return ph.p_vaddr;
    return 0;
}

static uint64_t find_remote_dlopen(int pid) {
    // Hedef process /proc/pid/maps'te libdl.so veya libc.so bul
    // ve ELF'ten dlopen sembolünü çıkar
    std::vector<std::string> candidates = { "libdl.so", "libc.so", "libdl_android.so" };

    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;

    struct LibEntry { uint64_t base; std::string path; };
    std::vector<LibEntry> entries;

    while (std::getline(maps, line)) {
        if (line.find("r-xp") == std::string::npos &&
            line.find("r--p") == std::string::npos) continue;
        for (auto& cand : candidates) {
            if (line.find(cand) == std::string::npos) continue;
            uint64_t base = 0;
            char path[512] = {};
            sscanf(line.c_str(), "%lx-%*x %*s %*s %*s %*s %511s", &base, path);
            if (base && path[0]) {
                entries.push_back({ base, path });
            }
        }
    }

    for (auto& e : entries) {
        ilog("[inject] trying " + e.path + " base=0x" + hex(e.base));
        uint64_t off = elf_sym_offset(e.path, "dlopen");
        if (!off) off = elf_sym_offset(e.path, "__dlopen"); // bionic alias
        if (!off) continue;
        uint64_t bias = elf_bias(e.path);
        uint64_t addr = e.base - bias + off;
        ilog("[inject] found dlopen in " + e.path + " offset=0x" + hex(off) + " addr=0x" + hex(addr));
        return addr;
    }

    // Fallback: agent'ın dlopen'ını offset ile kullan
    uint64_t local_dlopen = (uint64_t)dlsym(RTLD_DEFAULT, "dlopen");
    Dl_info info{};
    if (dladdr((void*)local_dlopen, &info) && info.dli_fbase) {
        uint64_t off = local_dlopen - (uint64_t)info.dli_fbase;
        std::string lib_name = info.dli_fname ? info.dli_fname : "";
        size_t slash = lib_name.rfind('/');
        if (slash != std::string::npos) lib_name = lib_name.substr(slash + 1);
        ilog("[inject] fallback: searching " + lib_name + " off=0x" + hex(off));
        std::ifstream maps2("/proc/" + std::to_string(pid) + "/maps");
        while (std::getline(maps2, line)) {
            if (line.find(lib_name) == std::string::npos) continue;
            if (line.find("r-xp") == std::string::npos &&
                line.find("r--p") == std::string::npos) continue;
            uint64_t base = 0;
            sscanf(line.c_str(), "%lx", &base);
            if (base) return base + off;
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════
//  inject_so
// ═══════════════════════════════════════════════════════
bool inject_so(int pid, const std::string& so_path) {
    ilog("[inject] starting pid=" + std::to_string(pid));

    // 1. Ana thread'i bul
    int tid = get_main_tid(pid);
    if (tid < 0) {
        ilog("[inject] cannot find main tid");
        return false;
    }
    ilog("[inject] main tid=" + std::to_string(tid));

    // 2. PTRACE_ATTACH
    int attach_ret = ptrace(PTRACE_ATTACH, tid, nullptr, nullptr);
    ilog("[inject] ptrace attach ret=" + std::to_string(attach_ret) +
        " errno=" + std::to_string(errno) +
        " (" + std::string(strerror(errno)) + ")");
    if (attach_ret < 0) {
        return false;
    }
    if (!wait_stopped(tid)) {
        ilog("[inject] wait after attach failed");
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }
    ilog("[inject] attached ok");

    // 3. mmap ile RWX page aç
    uint64_t page = do_syscall(pid, tid,
        222,          // __NR_mmap
        0,            // addr
        4096,         // len
        7,            // PROT_RWX
        0x22,         // MAP_PRIVATE|MAP_ANON
        (uint64_t)-1, // fd
        0);           // offset

    ilog("[inject] mmap page=0x" + hex(page));

    if (!page || page == (uint64_t)-1) {
        ilog("[inject] mmap failed");
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }

    // 4. SO path'ini page'e yaz
    uint64_t path_addr = page + 512;
    mem_write(pid, path_addr, so_path.c_str(), so_path.size() + 1);
    ilog("[inject] path written @ 0x" + hex(path_addr));

    // 5. dlopen adresini bul
    uint64_t remote_dlopen = find_remote_dlopen(pid);
    if (!remote_dlopen) {
        ilog("[inject] dlopen not found");
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }
    ilog("[inject] remote dlopen=0x" + hex(remote_dlopen));

    // 6. dlopen çağır
    ilog("[inject] calling dlopen...");
    uint64_t handle = remote_call(pid, tid,
        remote_dlopen,
        path_addr,
        0x101, // RTLD_NOW|RTLD_GLOBAL
        page);

    ilog("[inject] dlopen handle=0x" + hex(handle));

    if (!handle || handle == (uint64_t)-1) {
        // dlerror çağır — neden fail ettiğini öğren
        // dlerror adresini bul
        uint64_t dlerror_addr = 0;
        {
            std::ifstream maps2("/proc/" + std::to_string(pid) + "/maps");
            std::string line2;
            while (std::getline(maps2, line2)) {
                if (line2.find("libdl.so") == std::string::npos) continue;
                if (line2.find("r-xp") == std::string::npos &&
                    line2.find("r--p") == std::string::npos) continue;
                uint64_t base2 = 0;
                char path2[512] = {};
                sscanf(line2.c_str(), "%lx-%*x %*s %*s %*s %*s %511s", &base2, path2);
                if (!base2) continue;
                uint64_t off2 = elf_sym_offset(path2, "dlerror");
                if (!off2) continue;
                uint64_t bias2 = elf_bias(path2);
                dlerror_addr = base2 - bias2 + off2;
                ilog("[inject] dlerror @ 0x" + hex(dlerror_addr));
                break;
            }
        }
        if (dlerror_addr) {
            uint64_t err_ptr = remote_call(pid, tid, dlerror_addr, 0, 0, page);
            ilog("[inject] dlerror ptr=0x" + hex(err_ptr));
            if (err_ptr) {
                char err_buf[256] = {};
                mem_read(pid, err_ptr, err_buf, 255);
                ilog("[inject] dlerror: " + std::string(err_buf));
            }
        }
    }

    ptrace(PTRACE_DETACH, tid, nullptr, nullptr);

    if (!handle || handle == (uint64_t)-1) {
        ilog("[inject] injection failed");
        return false;
    }

    ilog("[inject] SUCCESS! " + so_path + " loaded");
    return true;
}