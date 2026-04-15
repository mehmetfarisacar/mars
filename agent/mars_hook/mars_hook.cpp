// ═══════════════════════════════════════════════════════
//  mars_hook.so — hedef process'e inject edilen library
//  Yüklenince IPC socket'e bağlanır, hook komutlarını bekler
//  Hook tetiklenince before/after callback'leri agent'a gönderir
// ═══════════════════════════════════════════════════════
#include "../utils/ipc.h"
#include <cstdio>
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "mars_hook", __VA_ARGS__)
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>

#define IPC_CMD_PATH "mars_hook_cmd"
#define IPC_CB_PATH  "mars_hook_cb"

// ─── Hook kayıtları ───
struct InternalHook {
    int      hook_id;
    uint64_t target_addr;
    uint8_t  orig_bytes[16];
    uint64_t trampoline_addr;
    char     lib[128];
    char     symbol[128];
};

static std::vector<InternalHook> g_hooks;
static std::mutex                 g_hooks_mutex;

// ─── ARM64 inline hook ───
// Her hook için bir thunk: before ipc → orig call → after ipc

// Trampoline: orijinal bytes + geri dön
static uint64_t make_trampoline(const uint8_t* orig, uint64_t return_addr) {
    void* p = mmap(nullptr, 4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    uint8_t* b = (uint8_t*)p;
    memcpy(b, orig, 16); b += 16;
    uint32_t ldr = 0x58000051; // LDR X17, #8
    uint32_t br = 0xD61F0220; // BR X17
    memcpy(b, &ldr, 4); b += 4;
    memcpy(b, &br, 4); b += 4;
    memcpy(b, &return_addr, 8);
    return (uint64_t)p;
}

// Hook dispatcher — her hook için bu fonksiyon çağrılır
// ARM64'te thunk shellcode bu C fonksiyonuna çağrı yapar
struct HookCallCtx {
    int      hook_id;
    uint64_t args[8];
    uint64_t trampoline_addr;
    char     lib[128];
    char     symbol[128];
};

extern "C" uint64_t mars_dispatch(HookCallCtx* ctx) {
    LOGI("dispatch hook_id=%d symbol=%s", ctx->hook_id, ctx->symbol);
    // ─── BEFORE ───
    IPCMsg before_msg{};
    before_msg.type = IPCMsgType::HOOK_BEFORE;
    before_msg.hook_id = ctx->hook_id;
    for (int i = 0; i < 8; i++) before_msg.args[i] = ctx->args[i];
    strncpy(before_msg.lib, ctx->lib, 127);
    strncpy(before_msg.symbol, ctx->symbol, 127);

    ipc_client_cb_send(before_msg);

    // Agent'tan setArg cevabı bekle (kısa timeout)
    IPCMsg reply{};
    if (ipc_client_cb_recv(reply, 50)) {
        if (reply.type == IPCMsgType::SET_ARG) {
            ctx->args[reply.hook_id] = reply.override_val; // hook_id = arg index
        }
    }

    // ─── Orijinal fonksiyon çağır ───
    typedef uint64_t(*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t,
        uint64_t, uint64_t, uint64_t, uint64_t);
    auto fn = (fn_t)ctx->trampoline_addr;
    uint64_t ret = fn(ctx->args[0], ctx->args[1],
        ctx->args[2], ctx->args[3],
        ctx->args[4], ctx->args[5],
        ctx->args[6], ctx->args[7]);

    // ─── AFTER ───
    IPCMsg after_msg{};
    after_msg.type = IPCMsgType::HOOK_AFTER;
    after_msg.hook_id = ctx->hook_id;
    after_msg.ret_val = ret;
    for (int i = 0; i < 8; i++) after_msg.args[i] = ctx->args[i];
    strncpy(after_msg.lib, ctx->lib, 127);
    strncpy(after_msg.symbol, ctx->symbol, 127);

    ipc_client_cb_send(after_msg);

    // setRet cevabı bekle
    IPCMsg ret_reply{};
    if (ipc_client_cb_recv(ret_reply, 50)) {
        if (ret_reply.type == IPCMsgType::SET_RET) {
            ret = ret_reply.override_val;
        }
    }

    return ret;
}

// ARM64 thunk per hook (shellcode)
// thunk: args → ctx yaz → mars_dispatch çağır → return
static uint64_t make_thunk(int hook_id, uint64_t trampoline_addr,
    const char* lib, const char* symbol) {
    // Page: [0..511]=code, [512..]=HookCallCtx
    uint8_t* page = (uint8_t*)mmap(nullptr, 4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 0;

    HookCallCtx* ctx = (HookCallCtx*)(page + 512);
    ctx->hook_id = hook_id;
    ctx->trampoline_addr = trampoline_addr;
    strncpy(ctx->lib, lib, 127);
    strncpy(ctx->symbol, symbol, 127);

    // Thunk: x0-x7 args -> ctx, call mars_dispatch, return x0
    // Use absolute addresses via MOVZ/MOVK to avoid PC-relative issues
    uint64_t ctx_addr = (uint64_t)ctx;
    uint64_t dispatch_addr = (uint64_t)mars_dispatch;

    // Build instructions
    std::vector<uint32_t> insns;

    auto movz = [&](int r, uint64_t v, int shift) {
        // MOVZ/MOVK
        uint32_t opc = (shift == 0) ? 0xD2800000 : 0xF2800000;
        opc |= ((shift / 16) & 3) << 21;
        opc |= ((v >> shift) & 0xFFFF) << 5;
        opc |= r;
        insns.push_back(opc);
        };

    auto mov64 = [&](int r, uint64_t v) {
        insns.push_back(0xD2800000 | ((v & 0xFFFF) << 5) | r);           // MOVZ
        insns.push_back(0xF2A00000 | (((v >> 16) & 0xFFFF) << 5) | r);    // MOVK lsl16
        insns.push_back(0xF2C00000 | (((v >> 32) & 0xFFFF) << 5) | r);    // MOVK lsl32
        insns.push_back(0xF2E00000 | (((v >> 48) & 0xFFFF) << 5) | r);    // MOVK lsl48
        };

    // Save x0-x7 to stack
    insns.push_back(0xA9BF07E0); // STP x0, x1, [sp, #-16]!
    insns.push_back(0xA9BF0FE2); // STP x2, x3, [sp, #-16]!
    insns.push_back(0xA9BF17E4); // STP x4, x5, [sp, #-16]!
    insns.push_back(0xA9BF1FE6); // STP x6, x7, [sp, #-16]!
    insns.push_back(0xA9BF7BFD); // STP x29, x30, [sp, #-16]!

    // X9 = ctx_addr
    mov64(9, ctx_addr);

    // ctx->args[0] = x0 (x0 is still on stack at sp+64)
    // Load saved x0-x7 from stack, store to ctx->args
    // LDP x0,x1,[sp,#64]
    insns.push_back(0xA9440BE0); // LDP x0,x1,[sp,#64]
    insns.push_back(0xA9450FE2); // LDP x2,x3,[sp,#80] -- wait, 64+16=80
    insns.push_back(0xA9460FE2); // wrong, recalc

    insns.clear();
    // Simpler: save lr+x29, then just store x0-x7 direct to ctx
    // x0-x7 haven't been clobbered yet when we enter thunk
    // Stack layout doesn't matter if we store BEFORE pushing

    // Actually restart: store x0-x7 to ctx FIRST before any stack ops
    insns.push_back(0xA9BF7BFD); // STP x29, x30, [sp, #-16]!  save lr first

    // X9 = ctx_addr
    mov64(9, ctx_addr);

    // Store x0-x7 to ctx->args
    uint32_t args_off = offsetof(HookCallCtx, args);
    // STP x0,x1,[x9,#args_off]   encoding: A9 + imm7<<15 | rt2<<10 | rn<<5 | rt
    insns.push_back(0xA9000000 | ((args_off / 8 & 0x7F) << 15) | (1 << 10) | (9 << 5) | 0);
    // STP x2,x3,[x9,#args_off+16]
    insns.push_back(0xA9000000 | (((args_off + 16) / 8 & 0x7F) << 15) | (3 << 10) | (9 << 5) | 2);
    // STP x4,x5,[x9,#args_off+32]
    insns.push_back(0xA9000000 | (((args_off + 32) / 8 & 0x7F) << 15) | (5 << 10) | (9 << 5) | 4);
    // STP x6,x7,[x9,#args_off+48]
    insns.push_back(0xA9000000 | (((args_off + 48) / 8 & 0x7F) << 15) | (7 << 10) | (9 << 5) | 6);

    // X0 = ctx (arg to dispatch)
    insns.push_back(0xAA0903E0); // MOV x0, x9

    // X10 = dispatch_addr
    mov64(10, dispatch_addr);

    // BLR x10
    insns.push_back(0xD63F0140);

    // Restore
    insns.push_back(0xA8C17BFD); // LDP x29, x30, [sp], #16

    // RET
    insns.push_back(0xD65F03C0);

    // Write to page
    memcpy(page, insns.data(), insns.size() * 4);
    __builtin___clear_cache((char*)page, (char*)page + insns.size() * 4);

    LOGI("thunk @ 0x%lx ctx=0x%lx dispatch=0x%lx args_off=%d insns=%d",
        (uint64_t)page, ctx_addr, dispatch_addr, (int)args_off, (int)insns.size());
    return (uint64_t)page;
}


static bool install_hook(int hook_id, const std::string& lib,
    const std::string& symbol, uint64_t target_addr = 0) {
    uint64_t target = target_addr;
    if (!target) {
        void* handle = dlopen(lib.c_str(), RTLD_NOLOAD | RTLD_NOW);
        if (!handle) handle = dlopen(lib.c_str(), RTLD_NOW);
        if (!handle) return false;
        void* sym = dlsym(handle, symbol.c_str());
        if (!sym) return false;
        target = (uint64_t)sym;
        LOGI("dlsym addr=0x%lx", target);
    }
    else {
        LOGI("using agent addr=0x%lx", target);
    }

    InternalHook hook;
    hook.hook_id = hook_id;
    hook.target_addr = target;
    strncpy(hook.lib, lib.c_str(), 127);
    strncpy(hook.symbol, symbol.c_str(), 127);

    // Orijinal 16 byte kaydet
    memcpy(hook.orig_bytes, (void*)target, 16);

    // Trampoline
    hook.trampoline_addr = make_trampoline(hook.orig_bytes, target + 16);
    if (!hook.trampoline_addr) return false;

    // Thunk
    uint64_t thunk = make_thunk(hook_id, hook.trampoline_addr,
        lib.c_str(), symbol.c_str());
    if (!thunk) return false;

    // mprotect — write izni
    uint64_t page_addr = target & ~0xFFFULL;
    mprotect((void*)page_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

    // 16-byte patch: LDR X17, #8 + BR X17 + thunk_addr
    uint8_t patch[16];
    uint32_t ldr = 0x58000051; // LDR X17, #8
    uint32_t br = 0xD61F0220; // BR  X17
    memcpy(patch + 0, &ldr, 4);
    memcpy(patch + 4, &br, 4);
    memcpy(patch + 8, &thunk, 8);
    LOGI("patching @ 0x%lx thunk=0x%lx", target, thunk);

    // Sayfayı writable yap
    uintptr_t page = target & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGI("mprotect failed errno=%d", errno);
        return false;
    }

    memcpy((void*)target, patch, 16);

    // Cache flush (ARM64 icin zorunlu)
    __builtin___clear_cache((char*)target, (char*)(target + 16));

    // Restore protection
    mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);

    LOGI("patch done");

    // Restore protection
    mprotect((void*)page_addr, 4096, PROT_READ | PROT_EXEC);

    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    g_hooks.push_back(hook);
    return true;
}

// ─── IPC command loop ───
static void command_loop() {
    while (true) {
        IPCMsg msg{};
        if (!ipc_client_cmd_recv(msg, 5000)) continue;

        if (msg.type == IPCMsgType::HOOK_INSTALL) {
            LOGI("hook_install received: %s::%s id=%d", msg.lib, msg.symbol, msg.hook_id);
            bool ok = install_hook(msg.hook_id, msg.lib, msg.symbol, msg.target_addr);
            LOGI("hook_install result: %s", ok ? "ok" : "failed");
            // Reply
            IPCMsg reply{};
            reply.type = ok ? IPCMsgType::READY : IPCMsgType::HOOK_REMOVE;
            reply.hook_id = msg.hook_id;
            ipc_client_cmd_send(reply);
        }
        else if (msg.type == IPCMsgType::HOOK_REMOVE) {
            // TODO: restore original bytes
        }
    }
}

// ─── SO entry point ───
__attribute__((constructor))
static void mars_hook_init() {
    LOGI("init started");

    // IPC socket'e bağlan
    if (!ipc_client_connect(IPC_CMD_PATH, IPC_CB_PATH)) {
        LOGI("IPC connect failed");
        return;
    }

    LOGI("IPC connected!");

    // Hazır sinyali gönder (cb kanalından)
    IPCMsg ready{};
    ready.type = IPCMsgType::READY;
    ipc_client_cb_send(ready);

    // Command loop thread
    std::thread(command_loop).detach();
}

__attribute__((destructor))
static void mars_hook_fini() {
    ipc_client_disconnect();
}
