#pragma once
#include <string>
#include "../utils/hook_engine.h"

bool        js_runtime_init();
std::string js_runtime_load(const std::string& src);
std::string js_runtime_eval(const std::string& code);
void        js_runtime_shutdown();
void        js_runtime_tick();
void        js_notify_lib_loaded(const std::string& lib_name, uint64_t base, const std::string& path);
void        js_dispatch_hook(int hook_id, HookContext& hctx, bool is_before);