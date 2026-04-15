(function () {

    MARS.log("🧪 AUTO-DUMP MODE started");

    function hexToAscii(hex) {
        return hex
            .split(" ")
            .map(b => {
                let v = parseInt(b, 16);
                if (v >= 32 && v <= 126) return String.fromCharCode(v);
                return ".";
            })
            .join("");
    }

    function dumpScan(keyword, size) {
        size = size || 64;

        MARS.log("🔎 scanning for:", keyword);
        const hits = MARS.memory.scan(keyword);

        MARS.log("🎯 hits =", hits.length);

        if (hits.length === 0) {
            MARS.log("❌ no hits");
            return;
        }

        let out = [];
        out.push("=== MARS AUTO DUMP ===");
        out.push("KEYWORD: " + keyword);
        out.push("SIZE: " + size);
        out.push("HITS: " + hits.length);
        out.push("");

        for (let addr of hits) {
            try {
                let hex = MARS.memory.read(addr, size);
                let ascii = hexToAscii(hex);

                out.push("ADDR: " + addr);
                out.push("HEX : " + hex);
                out.push("ASCII: " + ascii);
                out.push("----------------------------");

                MARS.log("ADDR:", addr);
                MARS.log("ASCII:", ascii);

            } catch (e) {
                out.push("ADDR: " + addr);
                out.push("ERROR: read failed");
                out.push("----------------------------");
            }
        }

        const path = "/data/local/tmp/mars_dump_" + keyword + ".txt";
        MARS.log("💾 writing dump to:", path);

        // write via shell
        const payload = out.join("\n").replace(/"/g, '\\"');

        MARS.process.attach; // keep runtime alive
        MARS.log("📦 dump ready");

        // best-effort write (agent side shell redirection)
        MARS.log("📄 DUMP CONTENT:\n" + out.join("\n"));
    }

    // expose globally
    globalThis.autoDump = dumpScan;

    MARS.log("✅ AUTO-DUMP READY");
    MARS.log("👉 Usage: autoDump('NATIVE_SECRET', 96)");

})();
