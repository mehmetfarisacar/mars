var session = MARS.attach("com.ad2001.frida0x8");

session.hook("libc.so", "strcmp")
    .before(function(call) {
        var arg0 = call.readStr(call.arg(0), 256);
        var arg1 = call.readStr(call.arg(1), 256);
        if (arg0.indexOf("Hello") !== -1) {
            MARS.log("Hooking the strcmp function");
            MARS.log("Input: " + arg0);
            MARS.log("The flag is: " + arg1);
        }
    });

MARS.log("[MARS] strcmp hook kuruldu - frida0x8");