MARS.log("[*] AntiRoot bypass scripti yuklendi");

MARS.waitForLib("libantiroot.so", function(lib) {
    MARS.log("[+] libantiroot.so tespit edildi");

    var exports = lib.findExports("libantiroot.so");
    MARS.log("[*] " + exports.length + " export bulundu");

    var target = null;
    for (var i = 0; i < exports.length; i++) {
        if (exports[i].name.indexOf("isDeviceSecure") !== -1) {
            target = exports[i];
            break;
        }
    }

    if (!target) {
        MARS.log("[!] isDeviceSecure sembolu bulunamadi");
        return;
    }

    MARS.log("[*] Hook hedefi: " + target.name);
    MARS.log("[*] Adres: " + target.address);

    intercept("libantiroot.so", target.name).after(function(c) {
        var orig = c.ret();
        MARS.log("[hook] isDeviceSecure() orijinal donus = " + orig);
        if (orig != 0) {
            c.setRet(0);
            MARS.log("[+] BYPASS! ret=0 olarak degistirildi");
        } else {
            MARS.log("[*] Zaten secure, mudahale gereksiz");
        }
    });

    MARS.log("[+] Hook aktif");
});