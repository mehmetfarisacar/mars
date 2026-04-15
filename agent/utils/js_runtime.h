#pragma once
#include <string>

// QuickJS runtime lifecycle
bool js_runtime_init();
void js_runtime_shutdown();

// Script yükle / eval et
std::string js_runtime_load(const std::string& script);
std::string js_runtime_eval(const std::string& code);

// Lib yüklendiðinde waitForLib callback'lerini tetikle
void js_notify_lib_loaded(const std::string& lib_name);