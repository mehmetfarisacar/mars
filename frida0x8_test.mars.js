var session = MARS.attach("com.ad2001.frida0x8");

// strcmp yerine strlen dene - her string işleminde çağrılır
session.hook("libc.so", "strlen")
    .before(function(call) {
        var arg0 = call.readStr(call.arg(0), 64);
        if (arg0 && arg0.length > 0)
            MARS.log("[strlen] '" + arg0 + "'");
    });

MARS.log("[MARS] strlen hook kuruldu");