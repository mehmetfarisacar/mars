(function () {
    MARS.log("🧪 Native secret dump script started");

    function hexToAscii(hex) {
        return hex
            .split(" ")
            .map(b => {
                const v = parseInt(b, 16);
                if (v === 0) return ".";
                if (v < 32 || v > 126) return ".";
                return String.fromCharCode(v);
            })
            .join("");
    }

    function dumpAt(addr, size) {
        try {
            const hex = MARS.memory.read(addr, size);
            const ascii = hexToAscii(hex);
            MARS.log("ADDR:", addr);
            MARS.log("HEX :", hex);
            MARS.log("ASCII:", ascii);
            MARS.log("---------------------------");
        } catch (e) {
            MARS.log("❌ read failed at", addr);
        }
    }

    function dumpScan(needle, size = 64) {
        MARS.log("🔎 scanning for:", needle);
        const hits = MARS.memory.scan(needle);
        MARS.log("🎯 hits =", hits.length);

        hits.forEach(addr => {
            dumpAt(addr, size);
        });
    }

    // expose helpers (istersen sonra js_eval ile çağır)
    globalThis.dumpScan = dumpScan;
    globalThis.dumpAt = dumpAt;

    // otomatik çalışsın
    dumpScan("NATIVE_SECRET", 64);
})();
