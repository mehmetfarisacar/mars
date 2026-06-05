MARS.waitForLib("libmarslab01.so", function(lib) {
    MARS.log("[waitForLib] libmarslab01.so yuklendi!");

    lib.hook("native_check")
        .after(function(call) {
            MARS.log("[native_check] original ret=" + call.ret());
            call.setRet(1337);
            MARS.log("[native_check] bypassed!");
        });
});

MARS.log("[MARS] watcher basladi, lib bekleniyor...");