#include "js_runtime.h"
#include "../commands/command.h"
#include "../commands/memory.h"
#include "hook_engine.h"
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <vector>
#include "json.h"
#include <quickjs.h>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <mutex>
#include <dlfcn.h>

// ═══════════════════════════════════════════════════════
//  GLOBALS
// ═══════════════════════════════════════════════════════
static JSRuntime* rt = nullptr;
static JSContext* ctx = nullptr;

struct JSHookCallbacks {
    JSValue before_fn;
    JSValue after_fn;
};
static std::map<int, JSHookCallbacks> g_js_hooks;
static std::mutex g_hook_mutex;

static std::map<std::string, JSValue> g_lib_watchers;
static std::mutex g_lib_watcher_mutex;

// ═══════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════
static std::string js_to_string(JSContext* c, JSValueConst v) {
    const char* s = JS_ToCString(c, v);
    std::string out = s ? s : "";
    JS_FreeCString(c, s);
    return out;
}

// HookContext pointer'ını JS object'e göm
static JSClassID g_hook_ctx_class_id = 0;

static void hook_ctx_finalizer(JSRuntime*, JSValue val) {
    // HookContext agent stack'te yaşıyor, free etmiyoruz
}

static JSValue make_call_obj(JSContext* c, HookContext* hctx) {
    // HookContext pointer'ı JS object'e göm
    if (g_hook_ctx_class_id == 0) {
        JS_NewClassID(&g_hook_ctx_class_id);
        JSClassDef def{};
        def.class_name = "HookContext";
        def.finalizer = hook_ctx_finalizer;
        JS_NewClass(JS_GetRuntime(c), g_hook_ctx_class_id, &def);
    }

    JSValue obj = JS_NewObjectClass(c, g_hook_ctx_class_id);
    JS_SetOpaque(obj, hctx);

    // arg(n) — argüman değerini döndür
    JS_SetPropertyStr(c, obj, "arg",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                auto* h = (HookContext*)JS_GetOpaque(this_val, g_hook_ctx_class_id);
                if (!h || argc < 1) return JS_NewFloat64(cc, 0);
                uint32_t idx = 0;
                JS_ToUint32(cc, &idx, argv[0]);
                if (idx >= 8) return JS_NewFloat64(cc, 0);
                return JS_NewFloat64(cc, (double)h->args[idx]);
            }, "arg", 1));

    // setArg(n, val) — argümanı değiştir
    JS_SetPropertyStr(c, obj, "setArg",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                auto* h = (HookContext*)JS_GetOpaque(this_val, g_hook_ctx_class_id);
                if (!h || argc < 2) return JS_UNDEFINED;
                uint32_t idx = 0;
                JS_ToUint32(cc, &idx, argv[0]);
                if (idx >= 8) return JS_UNDEFINED;
                double val = 0;
                JS_ToFloat64(cc, &val, argv[1]);
                h->arg_modified[idx] = true;
                h->arg_new_val[idx] = (uint64_t)val;
                return JS_UNDEFINED;
            }, "setArg", 2));

    // ret() — return değerini döndür (after'da kullanılır)
    JS_SetPropertyStr(c, obj, "ret",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int, JSValueConst*) -> JSValue {
                auto* h = (HookContext*)JS_GetOpaque(this_val, g_hook_ctx_class_id);
                if (!h) return JS_NewFloat64(cc, 0);
                return JS_NewFloat64(cc, (double)h->ret_val);
            }, "ret", 0));

    // setRet(val) — return değerini değiştir
    JS_SetPropertyStr(c, obj, "setRet",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                auto* h = (HookContext*)JS_GetOpaque(this_val, g_hook_ctx_class_id);
                if (!h || argc < 1) return JS_UNDEFINED;
                double val = 0;
                JS_ToFloat64(cc, &val, argv[0]);
                h->ret_modified = true;
                h->ret_new_val = (uint64_t)val;
                // Remote page'e yaz — trampoline wrapper okuyacak
                hook_set_ret(h->hook_id, (uint64_t)val);
                return JS_UNDEFINED;
            }, "setRet", 1));

    // readStr(addr, maxLen) — bellekten string oku
    JS_SetPropertyStr(c, obj, "readStr",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 2) return JS_NewString(cc, "");
                double addr_d = 0, len_d = 0;
                JS_ToFloat64(cc, &addr_d, argv[0]);
                JS_ToFloat64(cc, &len_d, argv[1]);
                std::string bytes;
                if (!read_mem_bytes((uint64_t)addr_d, (size_t)len_d, bytes))
                    return JS_NewString(cc, "<read failed>");
                size_t null_pos = bytes.find('\0');
                if (null_pos != std::string::npos) bytes = bytes.substr(0, null_pos);
                return JS_NewString(cc, bytes.c_str());
            }, "readStr", 2));

    // symbol, lib, addr bilgileri
    JS_SetPropertyStr(c, obj, "symbol",
        JS_NewString(c, hctx->symbol.c_str()));
    JS_SetPropertyStr(c, obj, "lib",
        JS_NewString(c, hctx->lib.c_str()));
    JS_SetPropertyStr(c, obj, "addr",
        JS_NewFloat64(c, (double)hctx->target_addr));

    return obj;
}

// ═══════════════════════════════════════════════════════
//  HOOK DISPATCHER
// ═══════════════════════════════════════════════════════
void js_dispatch_hook(int hook_id, HookContext& hctx, bool is_before) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);
    auto it = g_js_hooks.find(hook_id);
    if (it == g_js_hooks.end()) return;

    JSValue fn = is_before ? it->second.before_fn : it->second.after_fn;
    if (JS_IsUndefined(fn) || JS_IsNull(fn)) return;

    JSValue call_obj = make_call_obj(ctx, &hctx);
    JSValue result = JS_Call(ctx, fn, JS_UNDEFINED, 1, &call_obj);

    if (JS_IsException(result)) {
        JSValue exc = JS_GetException(ctx);
        send_async("[hook error] " + js_to_string(ctx, exc));
        JS_FreeValue(ctx, exc);
    }

    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, call_obj);
}

// ═══════════════════════════════════════════════════════
//  MARS.log
// ═══════════════════════════════════════════════════════
static JSValue js_mars_log(JSContext* c, JSValueConst,
    int argc, JSValueConst* argv) {
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

// ═══════════════════════════════════════════════════════
//  HookBuilder — .before() .after() .remove()
// ═══════════════════════════════════════════════════════
static JSValue make_hook_builder(JSContext* c, int hook_id) {
    JSValue builder = JS_NewObject(c);
    JS_SetPropertyStr(c, builder, "_hook_id", JS_NewInt32(c, hook_id));

    JS_SetPropertyStr(c, builder, "before",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 1 || !JS_IsFunction(cc, argv[0]))
                    return JS_DupValue(cc, this_val);
                int32_t hid = 0;
                JSValue hv = JS_GetPropertyStr(cc, this_val, "_hook_id");
                JS_ToInt32(cc, &hid, hv); JS_FreeValue(cc, hv);
                std::lock_guard<std::mutex> lock(g_hook_mutex);
                g_js_hooks[hid].before_fn = JS_DupValue(cc, argv[0]);
                return JS_DupValue(cc, this_val);
            }, "before", 1));

    JS_SetPropertyStr(c, builder, "after",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 1 || !JS_IsFunction(cc, argv[0]))
                    return JS_DupValue(cc, this_val);
                int32_t hid = 0;
                JSValue hv = JS_GetPropertyStr(cc, this_val, "_hook_id");
                JS_ToInt32(cc, &hid, hv); JS_FreeValue(cc, hv);
                std::lock_guard<std::mutex> lock(g_hook_mutex);
                g_js_hooks[hid].after_fn = JS_DupValue(cc, argv[0]);
                return JS_DupValue(cc, this_val);
            }, "after", 1));

    JS_SetPropertyStr(c, builder, "remove",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int, JSValueConst*) -> JSValue {
                int32_t hid = 0;
                JSValue hv = JS_GetPropertyStr(cc, this_val, "_hook_id");
                JS_ToInt32(cc, &hid, hv); JS_FreeValue(cc, hv);
                {
                    std::lock_guard<std::mutex> lock(g_hook_mutex);
                    auto it = g_js_hooks.find(hid);
                    if (it != g_js_hooks.end()) {
                        if (!JS_IsUndefined(it->second.before_fn)) JS_FreeValue(cc, it->second.before_fn);
                        if (!JS_IsUndefined(it->second.after_fn))  JS_FreeValue(cc, it->second.after_fn);
                        g_js_hooks.erase(it);
                    }
                }
                hook_remove(hid);
                return JS_UNDEFINED;
            }, "remove", 0));

    return builder;
}

// forward decl — agent_android_v3.cpp'de tanımlı
extern bool ipc_hook_install(int hook_id, const std::string& lib, const std::string& symbol, uint64_t target_addr);

// ═══════════════════════════════════════════════════════
//  session.findExports(lib) — lib'in tüm export'larını döndür
// ═══════════════════════════════════════════════════════
static JSValue js_session_find_exports(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(c);
    const char* lib = JS_ToCString(c, argv[0]);
    if (!lib) return JS_NewArray(c);

    // maps'ten lib base'i bul
    int pid = get_attached_pid();
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    uint64_t lib_base = 0;
    std::string lib_path_str;
    while (std::getline(maps, line)) {
        if (line.find(lib) == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos && line.find("r--p") == std::string::npos) continue;
        char path[512] = {};
        sscanf(line.c_str(), "%lx-%*x %*s %*s %*s %*s %511s", &lib_base, path);
        lib_path_str = path;
        break;
    }

    JSValue arr = JS_NewArray(c);
    if (!lib_base || lib_path_str.empty()) { JS_FreeCString(c, lib); return arr; }

    // ELF parse - dynsym
    int fd = open(lib_path_str.c_str(), O_RDONLY);
    if (fd < 0) { JS_FreeCString(c, lib); return arr; }

    Elf64_Ehdr ehdr{};
    read(fd, &ehdr, sizeof(ehdr));
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr));

    int idx = 0;
    for (auto& sh : shdrs) {
        if (sh.sh_type != SHT_DYNSYM || sh.sh_link >= (uint32_t)ehdr.e_shnum) continue;
        std::vector<Elf64_Sym> syms(sh.sh_size / sizeof(Elf64_Sym));
        lseek(fd, sh.sh_offset, SEEK_SET);
        read(fd, syms.data(), sh.sh_size);
        auto& strsh = shdrs[sh.sh_link];
        std::vector<char> strtab(strsh.sh_size + 1, 0);
        lseek(fd, strsh.sh_offset, SEEK_SET);
        read(fd, strtab.data(), strsh.sh_size);

        // LOAD bias
        uint64_t bias = 0;
        for (int pi = 0; pi < ehdr.e_phnum; pi++) {
            Elf64_Phdr ph{};
            lseek(fd, ehdr.e_phoff + pi * sizeof(ph), SEEK_SET);
            read(fd, &ph, sizeof(ph));
            if (ph.p_type == PT_LOAD) { bias = ph.p_vaddr; break; }
        }

        for (auto& sym : syms) {
            if (!sym.st_value || sym.st_name >= strsh.sh_size) continue;
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            uint64_t addr = lib_base - bias + sym.st_value;
            JSValue obj = JS_NewObject(c);
            JS_SetPropertyStr(c, obj, "name", JS_NewString(c, &strtab[sym.st_name]));
            JS_SetPropertyStr(c, obj, "address", JS_NewBigUint64(c, addr));
            JS_SetPropertyInt64(c, arr, idx++, obj);
        }
        break;
    }
    close(fd);
    JS_FreeCString(c, lib);
    return arr;
}

// ═══════════════════════════════════════════════════════
//  session.hook()
// ═══════════════════════════════════════════════════════
static JSValue js_session_hook(JSContext* c, JSValueConst,
    int argc, JSValueConst* argv) {
    if (argc < 2)
        return JS_ThrowTypeError(c, "hook(lib, symbol) requires 2 args");

    std::string lib = js_to_string(c, argv[0]);
    std::string symbol = js_to_string(c, argv[1]);

    int pid = get_attached_pid();
    if (pid <= 0)
        return JS_ThrowTypeError(c, "no attached process");

    uint64_t addr = find_symbol_addr(pid, lib, symbol);
    if (addr == 0) {
        send_async("[hook error] symbol not found: " + lib + "::" + symbol);
        return JS_ThrowTypeError(c, "symbol not found");
    }

    int hook_id = hook_install(pid, lib, symbol, addr);
    if (hook_id < 0) {
        send_async("[hook error] hook_install failed: " + symbol);
        return JS_ThrowTypeError(c, "hook_install failed");
    }

    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        g_js_hooks[hook_id] = { JS_UNDEFINED, JS_UNDEFINED };
    }

    std::ostringstream oss;
    oss << "[hook] " << lib << "::" << symbol
        << " @ 0x" << std::hex << addr
        << " (id=" << std::dec << hook_id << ")";
    send_async(oss.str());

    // IPC üzerinden SO'ya da hook kur komutu gönder
    ipc_hook_install(hook_id, lib, symbol, addr);

    return make_hook_builder(c, hook_id);
}

// ═══════════════════════════════════════════════════════
//  waitForLib
// ═══════════════════════════════════════════════════════
static JSValue make_lib_obj(JSContext* c, const std::string& lib_name) {
    JSValue lib_obj = JS_NewObject(c);
    JS_SetPropertyStr(c, lib_obj, "_lib", JS_NewString(c, lib_name.c_str()));

    JS_SetPropertyStr(c, lib_obj, "findExports",
        JS_NewCFunction(c, js_session_find_exports, "findExports", 1));

    JS_SetPropertyStr(c, lib_obj, "hook",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst this_val,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 1) return JS_ThrowTypeError(cc, "hook(symbol) requires 1 arg");
                JSValue lv = JS_GetPropertyStr(cc, this_val, "_lib");
                std::string lib = "";
                const char* ls = JS_ToCString(cc, lv);
                if (ls) { lib = ls; JS_FreeCString(cc, ls); }
                JS_FreeValue(cc, lv);
                std::string symbol = js_to_string(cc, argv[0]);

                int pid = get_attached_pid();
                if (pid <= 0) return JS_ThrowTypeError(cc, "no attached process");

                uint64_t addr = find_symbol_addr(pid, lib, symbol);
                if (addr == 0) {
                    send_async("[waitForLib hook error] not found: " + symbol);
                    return JS_ThrowTypeError(cc, "symbol not found");
                }

                int hook_id = hook_install(pid, lib, symbol, addr);
                if (hook_id < 0) {
                    send_async("[waitForLib hook error] failed: " + symbol);
                    return JS_ThrowTypeError(cc, "hook_install failed");
                }

                {
                    std::lock_guard<std::mutex> lock(g_hook_mutex);
                    g_js_hooks[hook_id] = { JS_UNDEFINED, JS_UNDEFINED };
                }

                send_async("[waitForLib hook] " + lib + "::" + symbol +
                    " (id=" + std::to_string(hook_id) + ")");
                return make_hook_builder(cc, hook_id);
            }, "hook", 1));

    return lib_obj;
}

static // Pending lib callbacks - main thread'den çalıştırılacak
static std::mutex g_pending_mutex;
static std::vector<std::string> g_pending_libs;

void trigger_lib_watchers(const std::string& lib_name) {
    // Background thread'den çağrılıyor - queue'ya ekle
    std::lock_guard<std::mutex> lock(g_pending_mutex);
    g_pending_libs.push_back(lib_name);
}

// Main thread'den çağrılır (js_runtime_tick)
void js_runtime_tick() {
    std::vector<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        pending.swap(g_pending_libs);
    }
    for (auto& lib_name : pending) {
        std::lock_guard<std::mutex> lock(g_lib_watcher_mutex);
        for (auto& [pattern, fn] : g_lib_watchers) {
            if (lib_name.find(pattern) != std::string::npos) {
                send_async("[waitForLib] triggered: " + lib_name);
                JSValue lib_obj = make_lib_obj(ctx, lib_name);
                JSValue result = JS_Call(ctx, fn, JS_UNDEFINED, 1, &lib_obj);
                if (JS_IsException(result)) {
                    JSValue exc = JS_GetException(ctx);
                    send_async("[waitForLib error] " + js_to_string(ctx, exc));
                    JS_FreeValue(ctx, exc);
                }
                JS_FreeValue(ctx, result);
                JS_FreeValue(ctx, lib_obj);
            }
        }
    }
}

static JSValue js_mars_wait_for_lib(JSContext* c, JSValueConst,
    int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(c, argv[1]))
        return JS_ThrowTypeError(c, "waitForLib(libName, callback) requires 2 args");

    std::string lib_name = js_to_string(c, argv[0]);
    int pid = get_attached_pid();

    if (pid > 0) {
        std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream f(maps_path);
        bool already_loaded = false;
        std::string line;
        while (std::getline(f, line)) {
            if (line.find(lib_name) != std::string::npos) {
                already_loaded = true;
                break;
            }
        }

        if (already_loaded) {
            send_async("[waitForLib] already loaded: " + lib_name);
            JSValue lib_obj = make_lib_obj(c, lib_name);
            JSValue result = JS_Call(c, argv[1], JS_UNDEFINED, 1, &lib_obj);
            if (JS_IsException(result)) {
                JSValue exc = JS_GetException(ctx);
                send_async("[waitForLib error] " + js_to_string(c, exc));
                JS_FreeValue(c, exc);
            }
            JS_FreeValue(c, result);
            JS_FreeValue(c, lib_obj);
            return JS_UNDEFINED;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_lib_watcher_mutex);
        g_lib_watchers[lib_name] = JS_DupValue(c, argv[1]);
    }
    send_async("[waitForLib] watching: " + lib_name);
    return JS_UNDEFINED;
}

// ═══════════════════════════════════════════════════════
//  session
// ═══════════════════════════════════════════════════════
static JSValue js_session_detach(JSContext* c, JSValueConst, int, JSValueConst*) {
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& [hid, cbs] : g_js_hooks) {
            hook_remove(hid);
            if (!JS_IsUndefined(cbs.before_fn)) JS_FreeValue(c, cbs.before_fn);
            if (!JS_IsUndefined(cbs.after_fn))  JS_FreeValue(c, cbs.after_fn);
        }
        g_js_hooks.clear();
    }
    set_attached_pid(-1);
    send_async("[session] detached");
    return JS_UNDEFINED;
}

static JSValue js_session_hooks(JSContext* c, JSValueConst, int, JSValueConst*) {
    auto list = hook_list_all();
    JSValue arr = JS_NewArray(c);
    for (size_t i = 0; i < list.size(); i++) {
        JSValue obj = JS_NewObject(c);
        JS_SetPropertyStr(c, obj, "id", JS_NewInt32(c, list[i].hook_id));
        JS_SetPropertyStr(c, obj, "lib", JS_NewString(c, list[i].lib.c_str()));
        JS_SetPropertyStr(c, obj, "symbol", JS_NewString(c, list[i].symbol.c_str()));
        JS_SetPropertyStr(c, obj, "addr", JS_NewFloat64(c, (double)list[i].target_addr));
        JS_SetPropertyUint32(c, arr, (uint32_t)i, obj);
    }
    return arr;
}

// ═══════════════════════════════════════════════════════
//  MARS.mem
// ═══════════════════════════════════════════════════════
static JSValue make_mem_object(JSContext* c) {
    JSValue mem = JS_NewObject(c);

    JS_SetPropertyStr(c, mem, "read",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 2) return JS_UNDEFINED;
                double addr_d = 0, size_d = 0;
                JS_ToFloat64(cc, &addr_d, argv[0]);
                JS_ToFloat64(cc, &size_d, argv[1]);
                std::string bytes;
                if (!read_mem_bytes((uint64_t)addr_d, (size_t)size_d, bytes))
                    return JS_NewString(cc, "<read failed>");
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (unsigned char b : bytes)
                    oss << std::setw(2) << (int)b << " ";
                return JS_NewString(cc, oss.str().c_str());
            }, "read", 2));

    JS_SetPropertyStr(c, mem, "readStr",
        JS_NewCFunction(c, [](JSContext* cc, JSValueConst,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc < 2) return JS_NewString(cc, "");
                double addr_d = 0, len_d = 0;
                JS_ToFloat64(cc, &addr_d, argv[0]);
                JS_ToFloat64(cc, &len_d, argv[1]);
                std::string bytes;
                if (!read_mem_bytes((uint64_t)addr_d, (size_t)len_d, bytes))
                    return JS_NewString(cc, "<read failed>");
                size_t null_pos = bytes.find('\0');
                if (null_pos != std::string::npos) bytes = bytes.substr(0, null_pos);
                return JS_NewString(cc, bytes.c_str());
            }, "readStr", 2));

    return mem;
}

// ═══════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════
bool js_runtime_init() {
    if (rt && ctx) return true;

    rt = JS_NewRuntime();
    ctx = JS_NewContext(rt);

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue mars = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, mars, "log",
        JS_NewCFunction(ctx, js_mars_log, "log", 1));

    JS_SetPropertyStr(ctx, mars, "mem", make_mem_object(ctx));

    JS_SetPropertyStr(ctx, mars, "waitForLib",
        JS_NewCFunction(ctx, js_mars_wait_for_lib, "waitForLib", 2));

    JS_SetPropertyStr(ctx, mars, "attach",
        JS_NewCFunction(ctx, [](JSContext* cc, JSValueConst,
            int argc, JSValueConst* argv) -> JSValue {
                if (argc >= 1) {
                    const char* pkg = JS_ToCString(cc, argv[0]);
                    if (pkg) { cmd_attach(pkg); JS_FreeCString(cc, pkg); }
                }
                JSValue session = JS_NewObject(cc);
                JS_SetPropertyStr(cc, session, "hook",
                    JS_NewCFunction(cc, js_session_hook, "hook", 2));
                JS_SetPropertyStr(cc, session, "findExports",
                    JS_NewCFunction(cc, js_session_find_exports, "findExports", 1));
                JS_SetPropertyStr(cc, session, "detach",
                    JS_NewCFunction(cc, js_session_detach, "detach", 0));
                JS_SetPropertyStr(cc, session, "hooks",
                    JS_NewCFunction(cc, js_session_hooks, "hooks", 0));
                return session;
            }, "attach", 1));

    JS_SetPropertyStr(ctx, global, "MARS", mars);
    JS_FreeValue(ctx, global);
    return true;
}

// ═══════════════════════════════════════════════════════
//  SCRIPT RUN / EVAL
// ═══════════════════════════════════════════════════════
std::string js_runtime_load(const std::string& src) {
    JSValue v = JS_Eval(ctx, src.c_str(), src.size(),
        "<mars-script>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx);
        std::string out = js_to_string(ctx, e);
        JS_FreeValue(ctx, e);
        JS_FreeValue(ctx, v);
        return json_resp("error", out);
    }
    JS_FreeValue(ctx, v);

    // log biriktiyse son mesajı döndür
    return json_resp("ok", "script loaded");
}

std::string js_runtime_eval(const std::string& code) {
    JSValue v = JS_Eval(ctx, code.c_str(), code.size(),
        "<mars-eval>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx);
        std::string out = js_to_string(ctx, e);
        JS_FreeValue(ctx, e);
        JS_FreeValue(ctx, v);
        return json_resp("error", out);
    }

    // eval sonucunu string'e çevir ve döndür
    std::string result = js_to_string(ctx, v);
    JS_FreeValue(ctx, v);
    if (result.empty() || result == "undefined")
        return json_resp("ok", "eval ok");
    return json_resp("ok", result);
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

void js_notify_lib_loaded(const std::string& lib_name) {
    trigger_lib_watchers(lib_name);
}