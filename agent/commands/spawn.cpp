#include "command.h"
#include "../utils/json.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <unistd.h>

static int find_pid(const std::string& packageName) {
    FILE* fp = popen("ps -A", "r");
    if (!fp) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, packageName.c_str())) continue;
        std::istringstream iss(line);
        std::string user, pid_str;
        iss >> user >> pid_str;
        int pid = atoi(pid_str.c_str());
        if (pid > 0) { pclose(fp); return pid; }
    }
    pclose(fp);
    return -1;
}

std::string cmd_spawn(const std::string& packageName) {
    if (packageName.empty())
        return json_resp("error", "package name required");

    system(("am force-stop " + packageName).c_str());
    usleep(300000);

    system(("monkey -p " + packageName +
        " -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1").c_str());

    int pid = -1;
    for (int i = 0; i < 30; i++) {
        usleep(200000);
        pid = find_pid(packageName);
        if (pid > 0) break;
    }

    if (pid <= 0)
        return json_resp("error", "spawn failed: could not find pid for " + packageName);

    set_attached_pid(pid);

    return "{\"status\":\"ok\","
        "\"msg\":\"spawned\","
        "\"package\":\"" + packageName + "\","
        "\"pid\":" + std::to_string(pid) + "}";
}

std::string cmd_resume(const std::string&) {
    return json_resp("ok", "nothing to resume");
}