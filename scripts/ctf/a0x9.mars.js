var session = MARS.attach("com.ad2001.a0x9");

MARS.waitForLib("liba0x9.so", function(lib) {
    MARS.log("[*] liba0x9.so yuklendi, hooklaniyor...");

    session.hook("liba0x9.so", "check_flag")
        .after(function(call) {
            MARS.log("Original return value: " + call.ret());
            call.setRet(1337);
        });

    MARS.log("[*] hook kuruldu");
});

MARS.log("[MARS] script yuklendi");