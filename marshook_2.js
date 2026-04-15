var session = MARS.attach("com.mars.lab01");

session.hook("libmarslab01.so", "native_check")
    .after(function(call) {
        MARS.log("[native_check] original ret=" + call.ret());
        call.setRet(1337);
        MARS.log("[native_check] bypassed!");
    });

MARS.log("[MARS] bypass hook kuruldu");