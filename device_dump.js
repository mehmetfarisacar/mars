(function () {

    MARS.log("🧪 dump script started");

    function hexAscii(buf) {
        let hex = "";
        let ascii = "";
        for (let i = 0; i < buf.length; i++) {
            const b = buf[i];
            hex += b.toString(16).padStart(2, "0") + " ";
            ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
        }
        return { hex, ascii };
    }

    globalThis.dumpAt = function (addr, size) {
        const buf = MARS.memory.read(addr, size);
        const out = hexAscii(buf);
        MARS.log("ADDR 0x" + addr.toString(16));
        MARS.log("HEX  : " + out.hex);
        MARS.log("ASCII: " + out.ascii);
    };

    globalThis.dumpScan = function (needle, size = 64) {
        MARS.log("🔎 scanning for: " + needle);
        const hits = MARS.memory.scan(needle);

        MARS.log("🎯 hits = " + hits.length);
        for (const a of hits) {
            dumpAt(a, size);
        }
    };

    MARS.log("✅ helpers loaded:");
    MARS.log(" - dumpScan('NATIVE_SECRET')");
    MARS.log(" - dumpScan('NATIVE_CHURN')");
    MARS.log(" - dumpAt(addr, 64)");

})();
