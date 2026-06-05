#include "js_runtime.h"
#include "../commands/command.h"
#include "../commands/memory.h"
#include "hook_engine.h"
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <vector>
#include "json.h"
#include "ipc.h"
#include <quickjs.h>
#include <string>
#include <map>
#include <set>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <mutex>
#include <atomic>
#include <dlfcn.h>

static JSRuntime* rt = nullptr;
static JSContext* ctx = nullptr;
static std::atomic<int> g_next_js_hook_id{ 0 };

struct JSHookCallbacks { JSValue before_fn; JSValue after_fn; };
static std::map<int, JSHookCallbacks> g_js_hooks;
static std::mutex g_hook_mutex;

static std::map<std::string, JSValue> g_lib_watchers;
static std::mutex g_lib_watcher_mutex;

struct LibInfo { uint64_t base; std::string path; };
static std::mutex                     g_pending_mutex;
static std::vector<std::string>       g_pending_libs;
static std::set<std::string>          g_notified_libs;
static std::map<std::string, LibInfo> g_lib_info;

// ─── IPC helpers ─────────────────────────────────────────────────────────────

static uint64_t ipc_find_symbol(const std::string& lib, const std::string& sym) {
    IPCMsg req{}; req.type = IPCMsgType::FIND_SYMBOL_REQ;
    strncpy(req.lib, lib.c_str(), 127);
    strncpy(req.symbol, sym.c_str(), 127);
    if (!ipc_cmd_send(req)) return 0;
    IPCMsg resp{};
    if (!ipc_cmd_recv(resp, 3000)) return 0;
    if (resp.type != IPCMsgType::FIND_SYMBOL_RESP) return 0;
    return resp.target_addr;
}

// ─── helpers ─────────────────────────────────────────────────────────────────

static std::string js_to_string(JSContext* c, JSValueConst v) {
    const char* s = JS_ToCString(c, v);
    std::string out = s ? s : ""; JS_FreeCString(c, s); return out;
}

static JSClassID g_hook_ctx_class_id = 0;
static void hook_ctx_finalizer(JSRuntime*, JSValue) {}

static JSValue make_call_obj(JSContext* c, HookContext* hctx) {
    if (g_hook_ctx_class_id == 0) {
        JS_NewClassID(&g_hook_ctx_class_id);
        JSClassDef def{}; def.class_name = "HookContext"; def.finalizer = hook_ctx_finalizer;
        JS_NewClass(JS_GetRuntime(c), g_hook_ctx_class_id, &def);
    }
    JSValue obj = JS_NewObjectClass(c, g_hook_ctx_class_id);
    JS_SetOpaque(obj, hctx);

    JS_SetPropertyStr(c, obj, "arg", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv) -> JSValue {
        auto* h = (HookContext*)JS_GetOpaque(tv, g_hook_ctx_class_id);
        if (!h || argc < 1) return JS_NewFloat64(cc, 0);
        uint32_t idx = 0; JS_ToUint32(cc, &idx, argv[0]);
        if (idx >= 8) return JS_NewFloat64(cc, 0);
        return JS_NewFloat64(cc, (double)h->args[idx]);
        }, "arg", 1));
    JS_SetPropertyStr(c, obj, "setArg", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv) -> JSValue {
        auto* h = (HookContext*)JS_GetOpaque(tv, g_hook_ctx_class_id);
        if (!h || argc < 2) return JS_UNDEFINED;
        uint32_t idx = 0; JS_ToUint32(cc, &idx, argv[0]); if (idx >= 8) return JS_UNDEFINED;
        double val = 0; JS_ToFloat64(cc, &val, argv[1]);
        h->arg_modified[idx] = true; h->arg_new_val[idx] = (uint64_t)val;
        return JS_UNDEFINED;
        }, "setArg", 2));
    JS_SetPropertyStr(c, obj, "ret", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int, JSValueConst*) -> JSValue {
        auto* h = (HookContext*)JS_GetOpaque(tv, g_hook_ctx_class_id);
        if (!h) return JS_NewFloat64(cc, 0);
        return JS_NewFloat64(cc, (double)h->ret_val);
        }, "ret", 0));
    JS_SetPropertyStr(c, obj, "setRet", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv) -> JSValue {
        auto* h = (HookContext*)JS_GetOpaque(tv, g_hook_ctx_class_id);
        if (!h || argc < 1) return JS_UNDEFINED;
        double val = 0; JS_ToFloat64(cc, &val, argv[0]);
        h->ret_modified = true; h->ret_new_val = (uint64_t)val;
        return JS_UNDEFINED;
        }, "setRet", 1));
    JS_SetPropertyStr(c, obj, "symbol", JS_NewString(c, hctx->symbol.c_str()));
    JS_SetPropertyStr(c, obj, "lib", JS_NewString(c, hctx->lib.c_str()));
    return obj;
}

// ─── js_dispatch_hook — DETAYLI DEBUG LOGLU ──────────────────────────────────

void js_dispatch_hook(int hook_id, HookContext& hctx, bool is_before) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    auto it = g_js_hooks.find(hook_id);
    if (it == g_js_hooks.end()) {
        send_async("[hook dbg] no callback registered for hook_id=" + std::to_string(hook_id));
        return;
    }
    JSValue fn = is_before ? it->second.before_fn : it->second.after_fn;
    if (JS_IsUndefined(fn) || JS_IsNull(fn)) {
        send_async(std::string("[hook dbg] ") + (is_before ? "before" : "after") +
            " is null for hook_id=" + std::to_string(hook_id));
        return;
    }

    {
        std::ostringstream o;
        o << "[hook dbg] calling " << (is_before ? "before" : "after")
            << " hook_id=" << hook_id
            << " ret_val=0x" << std::hex << hctx.ret_val;
        send_async(o.str());
    }

    JSValue co = make_call_obj(ctx, &hctx);
    JSValue r = JS_Call(ctx, fn, JS_UNDEFINED, 1, &co);
    if (JS_IsException(r)) {
        JSValue exc = JS_GetException(ctx);
        JSValue exc_msg = JS_GetPropertyStr(ctx, exc, "message");
        JSValue exc_stack = JS_GetPropertyStr(ctx, exc, "stack");
        send_async("[hook error] exc=" + js_to_string(ctx, exc) +
            " msg=" + js_to_string(ctx, exc_msg) +
            " stack=" + js_to_string(ctx, exc_stack));
        JS_FreeValue(ctx, exc_msg);
        JS_FreeValue(ctx, exc_stack);
        JS_FreeValue(ctx, exc);
    }
    else {
        send_async(std::string("[hook dbg] ") + (is_before ? "before" : "after") + " returned ok");
    }
    JS_FreeValue(ctx, r); JS_FreeValue(ctx, co);
}

static JSValue js_mars_log(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    std::ostringstream oss;
    for (int i = 0; i < argc; i++) {
        const char* s = JS_ToCString(c, argv[i]);
        if (s) { if (i) oss << " "; oss << s; JS_FreeCString(c, s); }
    }
    std::string msg = oss.str();
    std::cout << "[MARS][JS] " << msg << std::endl;
    send_async(msg);
    return JS_UNDEFINED;
}

static JSValue make_hook_builder(JSContext* c, int hook_id) {
    JSValue b = JS_NewObject(c);
    JS_SetPropertyStr(c, b, "_hook_id", JS_NewInt32(c, hook_id));
    JS_SetPropertyStr(c, b, "before", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv) -> JSValue {
        if (argc < 1 || !JS_IsFunction(cc, argv[0])) return JS_DupValue(cc, tv);
        int32_t hid = 0; JSValue hv = JS_GetPropertyStr(cc, tv, "_hook_id"); JS_ToInt32(cc, &hid, hv); JS_FreeValue(cc, hv);
        std::lock_guard<std::mutex> lock(g_hook_mutex); g_js_hooks[hid].before_fn = JS_DupValue(cc, argv[0]);
        return JS_DupValue(cc, tv);
        }, "before", 1));
    JS_SetPropertyStr(c, b, "after", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv) -> JSValue {
        if (argc < 1 || !JS_IsFunction(cc, argv[0])) return JS_DupValue(cc, tv);
        int32_t hid = 0; JSValue hv = JS_GetPropertyStr(cc, tv, "_hook_id"); JS_ToInt32(cc, &hid, hv); JS_FreeValue(cc, hv);
        std::lock_guard<std::mutex> lock(g_hook_mutex); g_js_hooks[hid].after_fn = JS_DupValue(cc, argv[0]);
        return JS_DupValue(cc, tv);
        }, "after", 1));
    return b;
}

extern bool ipc_hook_install(int hook_id, const std::string& lib,
    const std::string& symbol, uint64_t target_addr);

// ─── findExports ─────────────────────────────────────────────────────────────

static JSValue js_session_find_exports(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(c);
    std::string lib = js_to_string(c, argv[0]);
    JSValue arr = JS_NewArray(c);

    LibInfo info{ 0, "" };
    {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        for (auto& [name, inf] : g_lib_info) {
            if (name.find(lib) != std::string::npos) { info = inf; break; }
        }
    }
    if (!info.base) { send_async("[findExports] base not found: " + lib); return arr; }
    if (info.path.empty()) { send_async("[findExports] path not found: " + lib); return arr; }

    std::string elf_path = info.path;
    off_t elf_offset = 0;
    size_t excl = info.path.rfind('!');
    if (excl != std::string::npos) {
        std::string apk = info.path.substr(0, excl);
        std::string inner = info.path.substr(excl + 1);
        if (!inner.empty() && inner[0] == '/') inner = inner.substr(1);

        struct __attribute__((packed)) EOCD { uint32_t sig; uint16_t d, sd, ed, et; uint32_t cs, co; uint16_t cl; };
        struct __attribute__((packed)) CD { uint32_t sig; uint16_t vm, vn, fl, cm, mt, md; uint32_t c, cs, us; uint16_t nl, el, coml, ds, ia; uint32_t ea, lo; };
        struct __attribute__((packed)) LFH { uint32_t sig; uint16_t v, f, cm, mt, md; uint32_t c, cs, us; uint16_t nl, el; };

        int fd2 = open(apk.c_str(), O_RDONLY);
        if (fd2 >= 0) {
            off_t fsz = lseek(fd2, 0, SEEK_END); EOCD eocd{}; bool fe = false;
            for (off_t p2 = fsz - (off_t)sizeof(EOCD);p2 >= 0 && p2 > fsz - 65536;p2--) { lseek(fd2, p2, SEEK_SET);read(fd2, &eocd, sizeof(eocd));if (eocd.sig == 0x06054b50) { fe = true;break; } }
            if (fe) {
                lseek(fd2, eocd.co, SEEK_SET);
                for (int i = 0;i < eocd.et;i++) {
                    CD cd{}; if (read(fd2, &cd, sizeof(cd)) != (int)sizeof(cd)) break; if (cd.sig != 0x02014b50) break;
                    std::string en(cd.nl, '\0'); read(fd2, &en[0], cd.nl); lseek(fd2, cd.el + cd.coml, SEEK_CUR);
                    if (en == inner && cd.cm == 0) {
                        LFH lfh{}; lseek(fd2, cd.lo, SEEK_SET); read(fd2, &lfh, sizeof(lfh));
                        elf_offset = cd.lo + sizeof(lfh) + lfh.nl + lfh.el;
                        elf_path = apk; break;
                    }
                }
            }
            close(fd2);
        }
    }

    int fd = open(elf_path.c_str(), O_RDONLY);
    if (fd < 0) { send_async("[findExports] cannot open: " + elf_path); return arr; }

    Elf64_Ehdr ehdr{}; lseek(fd, elf_offset, SEEK_SET);
    if (read(fd, &ehdr, sizeof(ehdr)) != (int)sizeof(ehdr) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd); send_async("[findExports] not ELF"); return arr;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    lseek(fd, elf_offset + ehdr.e_shoff, SEEK_SET);
    read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr));

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    lseek(fd, elf_offset + ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr));
    uint64_t bias = 0;
    for (auto& ph : phdrs) if (ph.p_type == PT_LOAD) { bias = ph.p_vaddr; break; }

    int idx = 0;
    for (auto& sh : shdrs) {
        if (sh.sh_type != SHT_DYNSYM || sh.sh_link >= (uint32_t)ehdr.e_shnum) continue;
        std::vector<Elf64_Sym> syms(sh.sh_size / sizeof(Elf64_Sym));
        lseek(fd, elf_offset + sh.sh_offset, SEEK_SET);
        read(fd, syms.data(), sh.sh_size);
        auto& strsh = shdrs[sh.sh_link];
        std::vector<char> strtab(strsh.sh_size + 1, 0);
        lseek(fd, elf_offset + strsh.sh_offset, SEEK_SET);
        read(fd, strtab.data(), strsh.sh_size);
        for (auto& sym : syms) {
            if (!sym.st_value || sym.st_name >= strsh.sh_size) continue;
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            uint64_t addr = info.base - bias + sym.st_value;
            std::ostringstream addr_str; addr_str << "0x" << std::hex << addr;
            JSValue obj = JS_NewObject(c);
            JS_SetPropertyStr(c, obj, "name", JS_NewString(c, &strtab[sym.st_name]));
            JS_SetPropertyStr(c, obj, "address", JS_NewString(c, addr_str.str().c_str()));
            JS_SetPropertyInt64(c, arr, idx++, obj);
        }
        break;
    }
    close(fd);
    send_async("[findExports] " + lib + " -> " + std::to_string(idx) + " exports");
    return arr;
}

// ─── session.hook ─────────────────────────────────────────────────────────────

static JSValue js_session_hook(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_ThrowTypeError(c, "hook(lib,symbol) requires 2 args");
    std::string lib = js_to_string(c, argv[0]), symbol = js_to_string(c, argv[1]);
    int pid = get_attached_pid(); if (pid <= 0) return JS_ThrowTypeError(c, "no attached process");
    uint64_t addr = ipc_find_symbol(lib, symbol);
    if (!addr) addr = find_symbol_addr(pid, lib, symbol);
    if (!addr) { send_async("[hook error] symbol not found: " + lib + "::" + symbol); return JS_ThrowTypeError(c, "symbol not found"); }
    int hook_id = g_next_js_hook_id++;
    { std::lock_guard<std::mutex> lock(g_hook_mutex); g_js_hooks[hook_id] = { JS_UNDEFINED, JS_UNDEFINED }; }
    std::ostringstream oss; oss << "[hook] " << lib << "::" << symbol << " @ 0x" << std::hex << addr;
    send_async(oss.str());
    ipc_hook_install(hook_id, lib, symbol, addr);
    return make_hook_builder(c, hook_id);
}

// ─── lib object ──────────────────────────────────────────────────────────────

static JSValue make_lib_obj(JSContext* c, const std::string& lib_name) {
    JSValue o = JS_NewObject(c);
    JS_SetPropertyStr(c, o, "_lib", JS_NewString(c, lib_name.c_str()));
    JS_SetPropertyStr(c, o, "findExports", JS_NewCFunction(c, js_session_find_exports, "findExports", 1));
    JS_SetPropertyStr(c, o, "hook", JS_NewCFunction(c, [](JSContext* cc, JSValueConst tv, int argc, JSValueConst* argv)->JSValue {
        if (argc < 1) return JS_ThrowTypeError(cc, "hook(symbol) requires 1 arg");
        JSValue lv = JS_GetPropertyStr(cc, tv, "_lib");
        std::string lib; const char* ls = JS_ToCString(cc, lv); if (ls) { lib = ls;JS_FreeCString(cc, ls); } JS_FreeValue(cc, lv);
        std::string symbol = js_to_string(cc, argv[0]);
        uint64_t addr = ipc_find_symbol(lib, symbol);
        if (!addr) { send_async("[hook error] not found: " + symbol); return JS_NULL; }
        int hook_id = g_next_js_hook_id++;
        { std::lock_guard<std::mutex> lock(g_hook_mutex); g_js_hooks[hook_id] = { JS_UNDEFINED,JS_UNDEFINED }; }
        ipc_hook_install(hook_id, lib, symbol, addr);
        return make_hook_builder(cc, hook_id);
        }, "hook", 1));
    return o;
}

// ─── notify / tick / waitForLib ──────────────────────────────────────────────

void js_notify_lib_loaded(const std::string& lib_name, uint64_t base, const std::string& path) {
    std::lock_guard<std::mutex> lock(g_pending_mutex);
    g_notified_libs.insert(lib_name);
    g_lib_info[lib_name] = { base, path };
    g_pending_libs.push_back(lib_name);
}

void js_runtime_tick() {
    std::vector<std::string> pending;
    { std::lock_guard<std::mutex> lock(g_pending_mutex); pending.swap(g_pending_libs); }
    for (auto& lib_name : pending) {
        std::lock_guard<std::mutex> lock3(g_lib_watcher_mutex);
        for (auto& [pattern, fn] : g_lib_watchers) {
            if (lib_name.find(pattern) != std::string::npos) {
                send_async("[waitForLib] triggered: " + lib_name);
                JSValue lo = make_lib_obj(ctx, lib_name);
                JSValue r = JS_Call(ctx, fn, JS_UNDEFINED, 1, &lo);
                if (JS_IsException(r)) {
                    JSValue exc = JS_GetException(ctx);
                    send_async("[waitForLib error] " + js_to_string(ctx, exc));
                    JS_FreeValue(ctx, exc);
                }
                JS_FreeValue(ctx, r); JS_FreeValue(ctx, lo);
            }
        }
    }
}

static JSValue js_mars_wait_for_lib(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(c, argv[1]))
        return JS_ThrowTypeError(c, "waitForLib(libName,callback) requires 2 args");
    std::string lib_name = js_to_string(c, argv[0]);
    bool already_loaded = false;
    std::string matched_name;
    {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        for (auto& n : g_notified_libs) {
            if (n.find(lib_name) != std::string::npos) { already_loaded = true; matched_name = n; break; }
        }
    }
    if (already_loaded) {
        send_async("[waitForLib] already loaded, firing: " + matched_name);
        JSValue lo = make_lib_obj(c, matched_name);
        JSValue r = JS_Call(c, argv[1], JS_UNDEFINED, 1, &lo);
        if (JS_IsException(r)) { JSValue exc = JS_GetException(c); send_async("[waitForLib error] " + js_to_string(c, exc)); JS_FreeValue(c, exc); }
        JS_FreeValue(c, r); JS_FreeValue(c, lo);
        return JS_UNDEFINED;
    }
    { std::lock_guard<std::mutex> lock(g_lib_watcher_mutex); g_lib_watchers[lib_name] = JS_DupValue(c, argv[1]); }
    send_async("[waitForLib] registered: " + lib_name);
    return JS_UNDEFINED;
}

// ─── session helpers ─────────────────────────────────────────────────────────

static JSValue js_session_detach(JSContext* c, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    for (auto& [hid, cbs] : g_js_hooks) {
        if (!JS_IsUndefined(cbs.before_fn)) JS_FreeValue(c, cbs.before_fn);
        if (!JS_IsUndefined(cbs.after_fn))  JS_FreeValue(c, cbs.after_fn);
    }
    g_js_hooks.clear(); set_attached_pid(-1); send_async("[session] detached");
    return JS_UNDEFINED;
}

static JSValue js_session_hooks(JSContext* c, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    JSValue arr = JS_NewArray(c); uint32_t i = 0;
    for (auto& [hid, cbs] : g_js_hooks) {
        JSValue obj = JS_NewObject(c);
        JS_SetPropertyStr(c, obj, "id", JS_NewInt32(c, hid));
        JS_SetPropertyUint32(c, arr, i++, obj);
    }
    return arr;
}

// ─── memory ──────────────────────────────────────────────────────────────────

static JSValue make_mem_object(JSContext* c) {
    JSValue mem = JS_NewObject(c);
    JS_SetPropertyStr(c, mem, "read", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int argc, JSValueConst* argv)->JSValue {
        if (argc < 2) return JS_UNDEFINED;
        double a = 0, s = 0; JS_ToFloat64(cc, &a, argv[0]); JS_ToFloat64(cc, &s, argv[1]);
        std::string bytes; if (!read_mem_bytes((uint64_t)a, (size_t)s, bytes)) return JS_NewString(cc, "<read failed>");
        std::ostringstream oss; oss << std::hex << std::setfill('0');
        for (unsigned char b : bytes) oss << std::setw(2) << (int)b << " ";
        return JS_NewString(cc, oss.str().c_str());
        }, "read", 2));
    JS_SetPropertyStr(c, mem, "readStr", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int argc, JSValueConst* argv)->JSValue {
        if (argc < 2) return JS_NewString(cc, "");
        double a = 0, l = 0; JS_ToFloat64(cc, &a, argv[0]); JS_ToFloat64(cc, &l, argv[1]);
        std::string bytes; if (!read_mem_bytes((uint64_t)a, (size_t)l, bytes)) return JS_NewString(cc, "<read failed>");
        size_t np = bytes.find('\0'); if (np != std::string::npos) bytes = bytes.substr(0, np);
        return JS_NewString(cc, bytes.c_str());
        }, "readStr", 2));
    return mem;
}

// ─── process object ──────────────────────────────────────────────────────────

static JSValue make_process_object(JSContext* c) {
    JSValue obj = JS_NewObject(c);
    JS_SetPropertyStr(c, obj, "pid", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int, JSValueConst*) -> JSValue {
        return JS_NewInt32(cc, get_attached_pid());
        }, "pid", 0));
    JS_SetPropertyStr(c, obj, "modules", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int, JSValueConst*) -> JSValue {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        std::ostringstream j; j << "["; bool first = true;
        for (auto& [name, inf] : g_lib_info) {
            if (!first) j << ","; first = false;
            j << "{\"name\":\"" << name << "\",\"base\":\"0x" << std::hex << inf.base
                << "\",\"path\":\"" << inf.path << "\"}";
        }
        j << "]";
        return JS_NewString(cc, j.str().c_str());
        }, "modules", 0));
    return obj;
}

// ─── module object ───────────────────────────────────────────────────────────

static JSValue make_module_object(JSContext* c) {
    JSValue obj = JS_NewObject(c);

    JS_SetPropertyStr(c, obj, "list", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int, JSValueConst*) -> JSValue {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        std::ostringstream j; j << "["; bool first = true;
        for (auto& [name, inf] : g_lib_info) {
            if (!first) j << ","; first = false;
            j << "{\"name\":\"" << name << "\",\"base\":\"0x" << std::hex << inf.base << "\"}";
        }
        j << "]";
        return JS_NewString(cc, j.str().c_str());
        }, "list", 0));

    JS_SetPropertyStr(c, obj, "find", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int argc, JSValueConst* argv) -> JSValue {
        if (argc < 1) return JS_NULL;
        std::string name = js_to_string(cc, argv[0]);
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        for (auto& [lib, inf] : g_lib_info) {
            if (lib.find(name) != std::string::npos) {
                std::ostringstream j;
                j << "{\"name\":\"" << lib
                    << "\",\"base\":\"0x" << std::hex << inf.base
                    << "\",\"path\":\"" << inf.path << "\"}";
                return JS_NewString(cc, j.str().c_str());
            }
        }
        return JS_NULL;
        }, "find", 1));

    JS_SetPropertyStr(c, obj, "base", JS_NewCFunction(c, [](JSContext* cc, JSValueConst, int argc, JSValueConst* argv) -> JSValue {
        if (argc < 1) return JS_NewString(cc, "0x0");
        std::string name = js_to_string(cc, argv[0]);
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        for (auto& [lib, inf] : g_lib_info) {
            if (lib.find(name) != std::string::npos) {
                std::ostringstream oss; oss << "0x" << std::hex << inf.base;
                return JS_NewString(cc, oss.str().c_str());
            }
        }
        return JS_NewString(cc, "0x0");
        }, "base", 1));

    JS_SetPropertyStr(c, obj, "exports", JS_NewCFunction(c, js_session_find_exports, "exports", 1));

    return obj;
}

// ─── intercept ───────────────────────────────────────────────────────────────

static JSValue js_intercept(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(c, "intercept(lib,symbol) or intercept(addr)");
    std::string lib, symbol;
    uint64_t addr = 0;

    if (argc == 1) {
        if (JS_IsNumber(argv[0])) {
            double a = 0; JS_ToFloat64(c, &a, argv[0]); addr = (uint64_t)a;
        }
        else if (JS_IsString(argv[0])) {
            std::string s = js_to_string(c, argv[0]);
            try { addr = std::stoull(s, nullptr, 0); }
            catch (...) { return JS_NULL; }
        }
        std::ostringstream oss; oss << "0x" << std::hex << addr;
        lib = "raw"; symbol = oss.str();
    }
    else {
        lib = js_to_string(c, argv[0]);
        symbol = js_to_string(c, argv[1]);
        addr = ipc_find_symbol(lib, symbol);
        if (!addr) {
            send_async("[intercept] symbol not found: " + lib + "::" + symbol);
            return JS_NULL;
        }
    }

    int hook_id = g_next_js_hook_id++;
    { std::lock_guard<std::mutex> lock(g_hook_mutex); g_js_hooks[hook_id] = { JS_UNDEFINED, JS_UNDEFINED }; }
    std::ostringstream oss;
    oss << "[intercept] " << lib << "::" << symbol << " @ 0x" << std::hex << addr;
    send_async(oss.str());
    ipc_hook_install(hook_id, lib, symbol, addr);
    return make_hook_builder(c, hook_id);
}

// ─── init ────────────────────────────────────────────────────────────────────

bool js_runtime_init() {
    if (rt && ctx) return true;
    rt = JS_NewRuntime();
    JS_SetMaxStackSize(rt, 0);  // disable QuickJS stack size check
    ctx = JS_NewContext(rt);
    JSValue global = JS_GetGlobalObject(ctx);

    JSValue mars = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, mars, "log", JS_NewCFunction(ctx, js_mars_log, "log", 1));
    JS_SetPropertyStr(ctx, mars, "mem", make_mem_object(ctx));
    JS_SetPropertyStr(ctx, mars, "waitForLib", JS_NewCFunction(ctx, js_mars_wait_for_lib, "waitForLib", 2));
    JS_SetPropertyStr(ctx, mars, "attach", JS_NewCFunction(ctx, [](JSContext* cc, JSValueConst, int argc, JSValueConst* argv)->JSValue {
        if (argc >= 1) { const char* pkg = JS_ToCString(cc, argv[0]); if (pkg) { cmd_attach(pkg); JS_FreeCString(cc, pkg); } }
        JSValue session = JS_NewObject(cc);
        JS_SetPropertyStr(cc, session, "hook", JS_NewCFunction(cc, js_session_hook, "hook", 2));
        JS_SetPropertyStr(cc, session, "findExports", JS_NewCFunction(cc, js_session_find_exports, "findExports", 1));
        JS_SetPropertyStr(cc, session, "detach", JS_NewCFunction(cc, js_session_detach, "detach", 0));
        JS_SetPropertyStr(cc, session, "hooks", JS_NewCFunction(cc, js_session_hooks, "hooks", 0));
        return session;
        }, "attach", 1));
    JS_SetPropertyStr(ctx, global, "MARS", mars);

    JS_SetPropertyStr(ctx, global, "process", make_process_object(ctx));
    JS_SetPropertyStr(ctx, global, "module", make_module_object(ctx));
    JS_SetPropertyStr(ctx, global, "memory", make_mem_object(ctx));
    JS_SetPropertyStr(ctx, global, "intercept", JS_NewCFunction(ctx, js_intercept, "intercept", 2));

    JS_FreeValue(ctx, global);
    return true;
}

std::string js_runtime_load(const std::string& src) {
    JSValue v = JS_Eval(ctx, src.c_str(), src.size(), "<mars-script>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx); std::string out = js_to_string(ctx, e);
        JS_FreeValue(ctx, e); JS_FreeValue(ctx, v); return json_resp("error", out);
    }
    JS_FreeValue(ctx, v); return json_resp("ok", "script loaded");
}

std::string js_runtime_eval(const std::string& code) {
    JSValue v = JS_Eval(ctx, code.c_str(), code.size(), "<mars-eval>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx); std::string out = js_to_string(ctx, e);
        JS_FreeValue(ctx, e); JS_FreeValue(ctx, v); return json_resp("error", out);
    }
    std::string r = js_to_string(ctx, v); JS_FreeValue(ctx, v);
    if (r.empty() || r == "undefined") return json_resp("ok", "eval ok");
    return json_resp("ok", r);
}

void js_runtime_shutdown() {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    for (auto& [hid, cbs] : g_js_hooks) {
        if (!JS_IsUndefined(cbs.before_fn)) JS_FreeValue(ctx, cbs.before_fn);
        if (!JS_IsUndefined(cbs.after_fn))  JS_FreeValue(ctx, cbs.after_fn);
    }
    g_js_hooks.clear();
    if (ctx) JS_FreeContext(ctx);
    if (rt)  JS_FreeRuntime(rt);
}