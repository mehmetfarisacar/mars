var session = MARS.attach("com.ad2001.a0x9");

MARS.log("[MARS] liba0x9.so bekleniyor...");

MARS.waitForLib("liba0x9.so", function() {
    MARS.log("[MARS] liba0x9.so yuklendi!");

    var exports = session.findExports("liba0x9.so");
    MARS.log("exports count: " + exports.length);

    if (exports && exports.length > 0) {
        var first = exports[0];
        MARS.log("hooking: " + first.name + " @ 0x" + first.address.toString(16));

        session.hook("liba0x9.so", first.name)
            .after(function(call) {
                MARS.log("Original return value: " + call.ret());
                call.setRet(1337);
            });
    } else {
        MARS.log("[ERROR] exports bulunamadi");
    }
});