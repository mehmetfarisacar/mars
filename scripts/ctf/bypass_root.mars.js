// ═══════════════════════════════════════════════════════
//  MARS Script — Native Root Detection Bypass
//  Kullanım: ./mars-cli-v3.exe <ip> <port> js_load bypass_root.mars.js
// ═══════════════════════════════════════════════════════

var session = MARS.attach("com.byteria.intermediate");

MARS.log("[MARS] Root bypass başlatılıyor...");

// ─────────────────────────────────────────
//  1. libc hook'ları — hemen kur
//  popen, open, stat root check'leri için
// ─────────────────────────────────────────
var rootPaths = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/data/local/su",
    "/system/bin/magisk",
    "/sbin/magisk",
    "/data/adb/magisk",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk"
];

var blockedCmds = [
    "which su",
    "which magisk",
    "whoami",
    "getprop ro.debuggable",
    "getprop ro.secure"
];

session.hook("libc.so", "popen")
    .before(function(call) {
        var cmd = call.readStr(call.arg(0), 256);
        for (var i = 0; i < blockedCmds.length; i++) {
            if (cmd.indexOf(blockedCmds[i]) !== -1) {
                MARS.log("[popen blocked] " + cmd);
                break;
            }
        }
    });

session.hook("libc.so", "open")
    .before(function(call) {
        var path = call.readStr(call.arg(0), 256);
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                MARS.log("[open blocked] " + path);
                break;
            }
        }
    });

session.hook("libc.so", "stat")
    .before(function(call) {
        var path = call.readStr(call.arg(0), 256);
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                MARS.log("[stat blocked] " + path);
                break;
            }
        }
    });

MARS.log("[MARS] libc hook'ları kuruldu");

// ─────────────────────────────────────────
//  2. libintermediate.so yüklenince
//     JNI fonksiyonunu hook'la
// ─────────────────────────────────────────
MARS.waitForLib("libintermediate.so", function(lib) {
    MARS.log("[waitForLib] libintermediate.so yüklendi! JNI hook kuruluyor...");

    lib.hook("Java_com_byteria_intermediate_RootDetectionActivity_runNativeRootChecks")
        .before(function(call) {
            MARS.log("[root JNI] runNativeRootChecks çağrıldı — bypass aktif");
        });

    MARS.log("[waitForLib] JNI hook kuruldu");
});

MARS.log("[MARS] Hazır. Şimdi Native Root Detection butonuna bas.");