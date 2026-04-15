#pragma once
#include <string>

// hedef process'e SO inject et
bool inject_so(int pid, const std::string& so_path);