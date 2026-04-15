// strcmp hook test — setRet ile her zaman 0 (eşit) döndür
var session = MARS.attach("com.byteria.intermediate");

session.hook("libc.so", "strcmp")
    .before(function(call) {
        var s1 = call.readStr(call.arg(0), 256);
        var s2 = call.readStr(call.arg(1), 256);
        MARS.log("[strcmp] '" + s1 + "' == '" + s2 + "'");
    })
    .after(function(call) {
        var ret = call.ret();
        if (ret != 0) {
            MARS.log("[strcmp] ret=" + ret + " -> bypass: setRet(0)");
            call.setRet(0); // her zaman eşit döndür
        }
    });

MARS.log("[MARS] strcmp hook kuruldu");