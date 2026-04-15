(function () {
  // --- helpers ---
  function log() { MARS.log.apply(null, arguments); }
  function scanOnce(needle) {
    const hits = MARS.memory.scan(needle);
    log("scan:", needle, "hits=", hits.length);
    if (hits.length > 0) log("sample:", hits.slice(0, 10));
    return hits;
  }

  // Always attach once (safe if already attached in your C++ side)
  try {
    log("✅ device.js başladı");
    const ok = MARS.process.attach("com.mars.javalab");
    log("attach(com.mars.javalab) =>", ok);
  } catch (e) {
    log("attach error:", String(e));
  }

  // ---------- BUTTON 1: Seed SharedPreferences ----------
  globalThis.test_seed_prefs = function () {
    log("🧪 [BTN1] Seed SharedPreferences test başladı");
    scanOnce("mars_pref_secret");
    scanOnce("super_secret_token");
    scanOnce("mars_password");
    log("✅ [BTN1] bitti");
  };

  // ---------- BUTTON 2: Allocate Once (Big Blob) ----------
  globalThis.test_big_blob = function () {
    log("🧪 [BTN2] Big Secret Blob test başladı");
    scanOnce("BIG_SECRET_BLOB_MARS");
    log("✅ [BTN2] bitti");
  };

  // ---------- BUTTON 3: Start Heap Churn ----------
  globalThis.test_heap_churn_live = function () {
    log("🧪 [BTN3] Heap churn LIVE scan başladı");
    const hits = MARS.memory.scan("churn_secret");
    log("churn_secret hits=", hits.length);
    if (hits.length) log("sample:", hits.slice(0, 10));
    log("✅ [BTN3] bitti");
  };

  // ---------- BUTTON 4: Stop Heap Churn (decay check) ----------
  globalThis.test_heap_churn_decay = function () {
    log("🧪 [BTN4] Heap churn DECAY test başladı");

    // immediate
    const now = MARS.memory.scan("churn_secret").length;
    log("t=0s hits=", now);

    // schedule prints using JS timers (QuickJS supports setTimeout only if enabled;
    // if not available in your build, we'll call these manually with js_eval)
    try {
      setTimeout(function () {
        log("t=3s hits=", MARS.memory.scan("churn_secret").length);
      }, 3000);

      setTimeout(function () {
        log("t=8s hits=", MARS.memory.scan("churn_secret").length);
        log("✅ [BTN4] bitti");
      }, 8000);

      log("⏱️ timers scheduled (3s / 8s)");
    } catch (e) {
      log("⚠️ setTimeout yoksa: manual çağır -> test_heap_churn_decay_manual_3 / _8");
      log("err:", String(e));
    }
  };

  // Manual fallback if setTimeout yoksa:
  globalThis.test_heap_churn_decay_manual_3 = function () {
    log("t=3s hits=", MARS.memory.scan("churn_secret").length);
  };
  globalThis.test_heap_churn_decay_manual_8 = function () {
    log("t=8s hits=", MARS.memory.scan("churn_secret").length);
    log("✅ [BTN4] bitti");
  };

  // ---------- bonus: show interesting modules ----------
  globalThis.test_modules_focus = function () {
    log("🧪 modules focus");
    const mods = MARS.process.modules();
    for (const m of mods) {
      const p = m.path || "";
      if (
        p.includes("com.mars.javalab") ||
        p.includes("libart") ||
        p.includes("libcrypto") ||
        p.includes("boringssl") ||
        p.includes("conscrypt")
      ) {
        log("mod:", p);
      }
    }
    log("✅ modules focus bitti");
  };

  log("✅ device.js loaded. Komutlar:");
  log(" - test_seed_prefs()");
  log(" - test_big_blob()");
  log(" - test_heap_churn_live()");
  log(" - test_heap_churn_decay()");
  log(" - test_heap_churn_decay_manual_3()");
  log(" - test_heap_churn_decay_manual_8()");
  log(" - test_modules_focus()");
})();
