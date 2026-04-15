#include "command.h"
#include "../utils/json.h"

#include <sstream>
#include <cstdio>
#include <cstdlib>

static int g_attached_pid = -1;

int get_attached_pid() {
    return g_attached_pid;
}

void set_attached_pid(int pid) {
    g_attached_pid = pid;
}

std::string cmd_attach(const std::string& packageName) {

    FILE* pipe = popen("ps -A", "r");
    if (!pipe)
        return json_resp("error", "ps failed");

    char line[512];
    int found = -1;

    while (fgets(line, sizeof(line), pipe)) {
        std::string l(line);
        if (l.find(packageName) != std::string::npos) {
            std::istringstream iss(l);
            std::string user, pid;
            iss >> user >> pid;
            found = atoi(pid.c_str());
            break;
        }
    }

    pclose(pipe);

    if (found <= 0)
        return json_resp("error", "process not found");

    set_attached_pid(found);
    return json_resp("ok", std::to_string(found));
}
