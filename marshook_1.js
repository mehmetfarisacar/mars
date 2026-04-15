var session = MARS.attach("com.mars.lab01");
session.hook("libmarslab01.so", "native_check")
    .before(function(call) {
        var arg0 = call.readStr(call.arg(0), 256);
        var arg1 = call.readStr(call.arg(1), 256);
        MARS.log("[native_check] input='" + arg0 + "' secret='" + arg1 + "'");
    });
MARS.log("[MARS] native_check hook kuruldu");