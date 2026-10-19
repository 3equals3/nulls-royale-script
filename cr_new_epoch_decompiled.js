/**
 * ==============================================================================================
 *  DECOMPILED & RECONSTRUCTED JAVASCRIPT LOGIC: /cr-new-epoch.js
 * ==============================================================================================
 *
 *  Source:             downloaded_script.qjsc (QuickJS Bytecode, 6489 bytes)
 *  Host Library:       libwildcat.so (ARM64 / ARMv7)
 *  Target Game:        Clash Royale / Null's Royale (libg.so)
 *  Client Release:     wildcat4.1_nullsroyale.rel.free_15.535.13_release
 *  Private Server:     royale.server.dnull.xyz:9339
 *  Runtime Engine:     Frida Core / Frida QuickJS Runtime
 *  Total Functions:    37 (Functions [0] .. [36])
 *
 * ----------------------------------------------------------------------------------------------
 *  ARCHITECTURE OVERVIEW:
 * ----------------------------------------------------------------------------------------------
 *  This script is an injected payload bundled with an esbuild/rollup CommonJS/ESM wrapper.
 *  Its main responsibilities are:
 *
 *   1. BOOTSTRAP ORCHESTRATION (Function [32]):
 *      Detects when `libg.so` is loaded into memory via a 3-tier fallback strategy:
 *        - Tier 1: Interceptor on `libc.so!__cxa_atexit` (triggered by .init_array constructors)
 *        - Tier 2: Interceptor on `libc.so!__cxa_atexit + 4`
 *        - Tier 3: Polling every 50ms via `setInterval`
 *
 *   2. NETWORK REDIRECTION ENGINE (Function [14]):
 *      Redirects Clash Royale traffic away from official Supercell servers to Null's Royale:
 *        - Hooks `getaddrinfo` (Function [12]): queries `libwildcat.so!wildcat_js_request`
 *          for preferred hostname/port, replaces domain string in place.
 *        - Hooks `connect` (Function [13]): rewrites destination port in `sockaddr_in` (9339 -> preferredPort).
 *
 *   3. IN-MEMORY BINARY PATCHES & REVIEW BYPASS (Function [11]):
 *      Applies 4 low-level patches directly to `libg.so` memory:
 *        - Target 1 (0x118D360 / 0xDA8D14): forces register x4/r7 = ptr(1) (Review flag / bypass)
 *        - Target 2 (0x870F84 / 0x41A1CC): replaced by function at Target 3 (0x11F07E0 / 0xE17DC8)
 *        - Target 4 (0x75D1D4 / 0x2D88E8): replaced with stub logging "bad review call"
 *
 *   4. LIBC GOT POLYFILLS FOR ANDROID COMPATIBILITY (Function [22]):
 *      Scans GOT entries in `libg.so` and fills missing Bionic libc symbols on older Android OS:
 *        - __cxa_thread_atexit_impl (Function [16] -> [15])
 *        - __fwrite_chk             (Function [17] -> fwrite)
 *        - __gnu_strerror_r         (Function [18] -> strerror_r)
 *        - __register_atfork        (Function [20] -> [19])
 *        - stderr                   (Function [21] -> __sF + 0xA8)
 *
 *   5. SQLITE SCRIPT CACHING (Function [23]):
 *      After 15 seconds, queries `libwildcat.so` for the signed script payload and caches it
 *      into SQLite table `scripts` in `/wildcat.db` for offline/subsequent fast launches.
 *
 *   6. NATIVE SYNCHRONIZATION & UNBLOCKING (Function [34], [35]):
 *      Unblocks the native thread in `libwildcat.so` waiting on `wildcat_release_blocking(err)`.
 * ==============================================================================================
 */

// ==============================================================================================
// SECTION 1: BUNDLER RUNTIME & MODULE WRAPPERS (esbuild / rollup)
// ==============================================================================================

/**
 * Function [1]: CommonJS lazy singleton wrapper factory (__commonJS)
 * Bytecode offset: 0x07ea, cpool: [Function [0]]
 *
 * @param {Function} cb - The module factory function
 * @param {Object} [cachedExports] - Cache slot for module exports
 * @returns {Function} - Lazy getter that executes cb once and caches the result
 */
var __commonJS = function(cb, cachedExports) {
  /**
   * Function [0]: Lazy evaluation body
   * Bytecode offset: 0x0808, closures: [cb, cachedExports]
   */
  return function() {
    if (cb) {
      cachedExports = cb(0);
      cb = 0; // Clear callback to prevent re-execution and allow GC
    }
    return cachedExports;
  };
};

/**
 * Function [3]: ESM module wrapper factory (__esm)
 * Bytecode offset: 0x082e, cpool: [Function [2]]
 *
 * @param {Function} moduleDef - The module initialization function
 * @param {Object} [moduleHolder] - Cache slot { exports: {...} }
 * @returns {Function} - Getter returning moduleHolder.exports
 */
var __esm = function(moduleDef, moduleHolder) {
  /**
   * Function [2]: ESM evaluation body
   * Bytecode offset: 0x084c, closures: [moduleHolder, moduleDef]
   */
  return function() {
    if (!moduleHolder) {
      moduleHolder = { exports: {} };
      moduleDef(moduleHolder, moduleHolder.exports);
    }
    return moduleHolder.exports;
  };
};

/**
 * Function [4]: Empty initialization stub
 * Bytecode offset: 0x0882
 */
var __initStub = function() {
  return;
};


// ==============================================================================================
// SECTION 2: PLATFORM & ARCHITECTURE HELPERS (Module "x" / Function [7])
// ==============================================================================================

/**
 * Function [5]: Architecture check ($arch)
 * Bytecode offset: 0x08c5
 *
 * @param {*} armVal - Value to return if running on 32-bit ARM ("arm")
 * @param {*} otherVal - Value to return for any other architecture (ARM64, x86, etc.)
 * @returns {*}
 */
var $arch = function(armVal, otherVal) {
  return Process.arch === "arm" ? armVal : otherVal;
};

/**
 * Function [6]: Dual-architecture value selector ($armv8_armv7)
 * Bytecode offset: 0x08f6
 *
 * Selects between ARM64 (armv8) and ARM32 (armv7) offsets or functions.
 * If the selected argument is a function, it executes it immediately and returns the result.
 *
 * @param {number|Function} arm64Val - Value or generator for ARM64
 * @param {number|Function} arm32Val - Value or generator for ARM32
 * @returns {*}
 */
var $armv8_armv7 = function(arm64Val, arm32Val) {
  var isFunction = typeof arm64Val === "function" || typeof arm32Val === "function";
  if (Process.arch === "arm64") {
    return isFunction ? arm64Val() : arm64Val;
  } else {
    return isFunction ? arm32Val() : arm32Val;
  }
};

/**
 * Function [7]: Architecture Module initializer
 * Bytecode offset: 0x0894, cpool: [Function [5], Function [6]], closure: [__initStub]
 *
 * Registers `$arch` and `$armv8_armv7` in the global namespace.
 */
var module_architecture = function() {
  __initStub();
  global.$arch = $arch;             // Function [5]
  global.$armv8_armv7 = $armv8_armv7; // Function [6]
};


// ==============================================================================================
// SECTION 3: IN-MEMORY BINARY PATCHES & REVIEW BYPASS (Module "v" / Function [11])
// ==============================================================================================

/**
 * Function [8]: Target 1 Interceptor Attach Hook
 * Bytecode offset: 0x0ac5
 *
 * Intercepts libg.so!target1 (0x118D360 arm64 / 0xDA8D14 arm32).
 * Writes ptr(1) into the review/bypass flag argument register:
 *   - In ARM64 calling convention: args[4] (register x4)
 *   - In ARM32 calling convention: args[7] (register r7)
 *
 * @param {NativePointer[]} args - CPU register arguments passed to target1
 */
var hook_reviewArgumentPatch = function(args) {
  var argIndex = $armv8_armv7(4, 7);
  args[argIndex] = ptr(1);
};

/**
 * Function [9]: Target 4 Replacement Stub
 * Bytecode offset: 0x0adc
 *
 * Replaces libg.so!target4 (0x75D1D4 arm64 / 0x2D88E8 arm32) with a safe stub
 * returning 0 to suppress review / anti-tamper failures.
 *
 * @returns {number} 0
 */
var stub_badReviewCall = function() {
  console.log("bad review call");
  // Implicitly returns undefined / 0 to caller
};

/**
 * Function [11]: In-memory patch installer ("v")
 * Bytecode offset: 0x09b1, cpool: [Function [8], Function [9], Function [10]]
 *
 * Applies binary modifications directly to libg.so code sections:
 *   - Target 1 (0x118D360 / 0xDA8D14): Interceptor.attach -> sets flag register = ptr(1)
 *   - Target 2 (0x870F84 / 0x41A1CC): Interceptor.replace -> redirect to Target 3
 *   - Target 3 (0x11F07E0 / 0xE17DC8): Replacement implementation for Target 2
 *   - Target 4 (0x75D1D4 / 0x2D88E8): Interceptor.replace -> "bad review call" stub
 *
 * @param {NativePointer} libgBase - Base address of libg.so in memory
 * @returns {{ revert: Function }} - Object with revert method (Function [10])
 */
var patch_libg_review = function(libgBase) {
  var target1 = libgBase.add($armv8_armv7(18404192, 14322964)); // 0x118D360 (arm64) / 0xDA8D14 (arm32)
  var target2 = libgBase.add($armv8_armv7(8851332, 4301260));   // 0x870F84 (arm64) / 0x41A1CC (arm32)
  var target3 = libgBase.add($armv8_armv7(18810848, 14777800)); // 0x11F07E0 (arm64) / 0xE17DC8 (arm32)
  var target4 = libgBase.add($armv8_armv7(7721428, 2984168));   // 0x75D1D4 (arm64) / 0x2D88E8 (arm32)

  // 1. Hook review argument
  var attachHandle = Interceptor.attach(target1, hook_reviewArgumentPatch); // Function [8]

  // 2. Replace Target 2 with Target 3
  Interceptor.replace(target2, target3);

  // 3. Replace Target 4 with safe stub
  var nativeStub = new NativeCallback(stub_badReviewCall, "int", []); // Function [9]
  Interceptor.replace(target4, nativeStub);

  /**
   * Function [10]: Revert cleanup handler
   * Bytecode offset: 0x0b00, closures: [attachHandle, target2, target4]
   */
  return {
    revert: function() {
      attachHandle.detach();
      Interceptor.revert(target2);
      Interceptor.revert(target4);
    }
  };
};


// ==============================================================================================
// SECTION 4: NETWORK REDIRECTION ENGINE (Module "E" / Function [14])
// ==============================================================================================

/**
 * Function [14]: Network Redirection Setup ("E")
 * Bytecode offset: 0x0b4b, cpool: [Function [12], Function [13]], closures: [h, v]
 *
 * Hooks system DNS resolution (getaddrinfo) and TCP connection (connect) to transparently
 * redirect Clash Royale game traffic to the Null's Royale private server.
 *
 * @param {string} defaultDomain - Server domain ("royale.server.dnull.xyz")
 */
var setupNetworkRedirection = function(defaultDomain) {
  var libgBase = Module.findBaseAddress("libg.so");

  // Apply libg in-memory review patches first
  var oth = patch_libg_review(libgBase); // Function [11]

  // Variable shared between onGetAddrInfo [12] and onConnect [13]
  var preferredPort = 9339;

  /**
   * Function [12]: getaddrinfo Interceptor Hook
   * Bytecode offset: 0x0c6d, closures: [defaultDomain, preferredPort]
   *
   * Intercepts DNS queries for "royale.server.dnull.xyz".
   * Queries `libwildcat.so!wildcat_js_request` to obtain dynamic hostname and port preference,
   * then overwrites the domain string in-place in the caller's buffer.
   *
   * @param {NativePointer[]} args - [const char *node, const char *service, ...]
   */
  var onGetAddrInfo = function(args) {
    var queryHost = args[0].readUtf8String();

    if (queryHost === "royale.server.dnull.xyz") {
      // 1. Locate dynamic request handler in libwildcat.so
      var wildcatReqPtr = Module.findExportByName("libwildcat.so", "wildcat_js_request");
      var wildcatRequest = null;
      if (wildcatReqPtr && !wildcatReqPtr.isNull()) {
        wildcatRequest = new NativeFunction(
          wildcatReqPtr,
          "pointer",
          ["pointer", "pointer", "size_t"],
          { exceptions: "propagate" }
        );
      }

      // 2. Prepare JSON request: {"type": "getHostnamePreference"}
      var reqPayload = { type: "getHostnamePreference" };
      var reqUtf8 = Memory.allocUtf8String(JSON.stringify(reqPayload));

      // 3. Prepare response buffer with fallback default values
      var respBuf = Memory.alloc(1024);
      var fallbackData = {
        preferredHostname: defaultDomain, // "royale.server.dnull.xyz"
        preferredPort: 9339
      };
      respBuf.writeUtf8String(JSON.stringify(fallbackData));

      // 4. Call native C++ handler in libwildcat.so to get actual preference
      if (wildcatReqPtr && !wildcatReqPtr.isNull()) {
        wildcatRequest(reqUtf8, respBuf, 1024);
      }

      // Ensure null-termination at byte 1023
      respBuf.add(1023).writeU8(0);

      // 5. Parse JSON response
      var resp = JSON.parse(respBuf.readUtf8String());

      // 6. IN-PLACE REDIRECTION: Overwrite domain string in args[0] buffer!
      args[0].writeUtf8String(resp.preferredHostname);

      // 7. Store port preference for onConnect hook
      preferredPort = resp.preferredPort;

      console.log("preferredHostname:", resp.preferredHostname);
    }
  };

  Interceptor.attach(
    Module.findExportByName("libc.so", "getaddrinfo"),
    onGetAddrInfo // Function [12]
  );

  // Native wrappers for byte order conversion
  var ntohs = new NativeFunction(
    Module.findExportByName("libc.so", "ntohs"),
    "uint16",
    ["uint16"],
    { exceptions: "propagate" }
  );

  var htons = new NativeFunction(
    Module.findExportByName("libc.so", "htons"),
    "uint16",
    ["uint16"],
    { exceptions: "propagate" }
  );

  /**
   * Function [13]: connect Interceptor Hook
   * Bytecode offset: 0x0e2e, closures: [ntohs, htons, preferredPort]
   *
   * Intercepts socket connect() calls.
   * Checks if destination port is 9339 (Supercell game port).
   * Rewrites sin_port in struct sockaddr_in to preferredPort (in Big-Endian).
   *
   * @param {NativePointer[]} args - [int sockfd, const struct sockaddr *addr, socklen_t addrlen]
   */
  var onConnect = function(args) {
    var sockaddrPtr = args[1]; // struct sockaddr_in *

    // sockaddr_in layout:
    //   +0x00: sin_family (2 bytes)
    //   +0x02: sin_port   (2 bytes, Big-Endian)
    //   +0x04: sin_addr   (4 bytes)
    var currentPort = ntohs(sockaddrPtr.add(2).readU16());

    if (currentPort === 9339) {
      // Rewrite destination port in memory before syscall executes
      var newPortBigEndian = htons(preferredPort);
      sockaddrPtr.add(2).writeU16(newPortBigEndian);
      console.log("preferredPort:", preferredPort);
    }
  };

  Interceptor.attach(
    Module.findExportByName("libc.so", "connect"),
    onConnect // Function [13]
  );
};


// ==============================================================================================
// SECTION 5: ANDROID LIBC GOT POLYFILL ENGINE (Module "M" / Function [22])
// ==============================================================================================

/**
 * Array holding persistent NativeCallback references to prevent GC collection
 */
var __nativeCallbacksList = [];

/**
 * Function [15]: Stub for __cxa_thread_atexit_impl
 * Bytecode offset: 0x113a
 */
var stub_cxa_thread_atexit_impl = function(arg) {
  console.log("POLYFILL IMPL:__cxa_thread_atexit_impl: stub called!");
};

/**
 * Function [16]: NativeCallback factory for __cxa_thread_atexit_impl
 * Bytecode offset: 0x10f8, cpool: [Function [15]], closure: [__nativeCallbacksList]
 */
var factory_cxa_thread_atexit_impl = function() {
  var cb = new NativeCallback(stub_cxa_thread_atexit_impl, "void", []); // Function [15]
  __nativeCallbacksList.push(cb);
  return cb;
};

/**
 * Function [17]: Polyfill resolver for __fwrite_chk
 * Bytecode offset: 0x1163
 * Resolves __fwrite_chk by falling back to standard fwrite in libc.so.
 */
var factory_fwrite_chk = function() {
  console.log("__fwrite_chk polyfill needed. will use fwrite as polyfill");
  return Module.findExportByName("libc.so", "fwrite");
};

/**
 * Function [18]: Polyfill resolver for __gnu_strerror_r
 * Bytecode offset: 0x119e
 * Resolves __gnu_strerror_r by falling back to strerror_r in libc.so.
 */
var factory_gnu_strerror_r = function() {
  console.log("__gnu_strerror_r polyfill needed. will use strerror_r as polyfill");
  return Module.findExportByName("libc.so", "strerror_r");
};

/**
 * Function [19]: Stub for __register_atfork
 * Bytecode offset: 0x121b
 */
var stub_register_atfork = function(arg) {
  console.log("POLYFILL IMPL:__register_atfork: stub called!");
};

/**
 * Function [20]: NativeCallback factory for __register_atfork
 * Bytecode offset: 0x11d9, cpool: [Function [19]], closure: [__nativeCallbacksList]
 */
var factory_register_atfork = function() {
  var cb = new NativeCallback(stub_register_atfork, "void", []); // Function [19]
  __nativeCallbacksList.push(cb);
  return cb;
};

/**
 * Function [21]: Polyfill resolver for stderr
 * Bytecode offset: 0x1244
 * Resolves missing stderr symbol by locating libc `__sF` array and adding offset 0xA8 (168).
 */
var factory_stderr = function() {
  console.log("stderr polyfill needed. will use __sF + 0xA8 as polyfill");
  var sF = Module.findExportByName("libc.so", "__sF");
  if (sF == null || sF.isNull()) {
    return NULL;
  }
  return sF.add(168); // 0xA8 = offsetof(stderr in Bionic FILE __sF[3])
};

/**
 * Function [22]: Global Offset Table (GOT) Polyfill Engine ("M")
 * Bytecode offset: 0x0ead, cpool: [Function [16], [17], [18], [20], [21]]
 *
 * Scans libg.so Global Offset Table entries for functions that do not exist on older
 * Android versions. If any entry is NULL, it injects a polyfill pointer.
 */
var installGotPolyfills = function() {
  var libgBase = Module.findBaseAddress("libg.so");

  // GOT slot addresses in libg.so
  var gotEntries = {
    __cxa_thread_atexit_impl: libgBase.add($armv8_armv7(26122424, 21895092)), // 0x18E98B8 / 0x14E17B4
    __fwrite_chk:             libgBase.add($armv8_armv7(26122480, 21895120)), // 0x18E98F0 / 0x14E17D0
    __gnu_strerror_r:         libgBase.add($armv8_armv7(26123016, 21895404)), // 0x18E9B08 / 0x14E18EC
    __register_atfork:        libgBase.add($armv8_armv7(26121032, 21894348)), // 0x18E9348 / 0x14E14CC
    stderr:                   libgBase.add($armv8_armv7(26117328, 21892484))  // 0x18E84D0 / 0x14E0D84
  };

  // Factory functions returning replacement pointers
  var polyfillFactories = {
    __cxa_thread_atexit_impl: factory_cxa_thread_atexit_impl, // Function [16]
    __fwrite_chk:             factory_fwrite_chk,             // Function [17]
    __gnu_strerror_r:         factory_gnu_strerror_r,         // Function [18]
    __register_atfork:        factory_register_atfork,        // Function [20]
    stderr:                   factory_stderr                  // Function [21]
  };

  for (var symName in gotEntries) {
    var slot = gotEntries[symName];
    // Check if the symbol failed to resolve and is currently NULL
    if (slot.readPointer().isNull()) {
      console.log("NULL!", symName);
      var polyfillPtr = polyfillFactories[symName]();

      if (polyfillPtr == null || polyfillPtr.isNull()) {
        console.log(symName, "polyfill is NULL!");
        Memory.protect(slot, Process.pointerSize, "rw-");
        slot.writePointer(NULL);
      } else {
        Memory.protect(slot, Process.pointerSize, "rw-");
        slot.writePointer(polyfillPtr);
        console.log("installed polyfill", polyfillPtr, "for:", symName);
      }
    }
  }

  console.log("done");
};


// ==============================================================================================
// SECTION 6: SQLITE SCRIPT CACHING (Module "P" / Function [23])
// ==============================================================================================

/**
 * Function [23]: SQLite Script Cacher ("P")
 * Bytecode offset: 0x1303
 *
 * Queries `libwildcat.so` for:
 *   - wildcat_js_get_data_path()
 *   - wildcat_js_get_signed_script_size()
 *   - wildcat_js_get_signed_script()
 *
 * Opens / creates `<data_path>/wildcat.db` and caches the signed script blob
 * under key "wildcat4.1_nullsroyale.rel.free_15.535.13_release" for offline/warm starts.
 */
var cacheSignedScript = function() {
  var fn_getDataPath = new NativeFunction(
    Module.findExportByName("libwildcat.so", "wildcat_js_get_data_path"),
    "pointer",
    []
  );
  var fn_getScriptSize = new NativeFunction(
    Module.findExportByName("libwildcat.so", "wildcat_js_get_signed_script_size"),
    "size_t",
    []
  );
  var fn_getScript = new NativeFunction(
    Module.findExportByName("libwildcat.so", "wildcat_js_get_signed_script"),
    "pointer",
    []
  );

  var pathPtr = fn_getDataPath();
  if (pathPtr.isNull()) return;
  var dataPath = pathPtr.readUtf8String();

  var scriptSize = fn_getScriptSize();
  if (scriptSize === 0) return;

  var scriptPtr = fn_getScript();
  if (scriptPtr.isNull()) return;
  var scriptBlob = scriptPtr.readByteArray(scriptSize);

  // Open SQLite database with readwrite | create
  var db = SqliteDatabase.open(dataPath + "/wildcat.db", {
    flags: ["readwrite", "create"]
  });

  // Ensure table exists
  db.exec("\n\t\tCREATE TABLE IF NOT EXISTS scripts(\n\t\t\tscript_name TEXT PRIMARY KEY NOT NULL,\n\t\t\tdata BLOB NOT NULL\n\t\t)\n\t");

  // Insert or replace current script
  var stmt = db.prepare("REPLACE INTO scripts (script_name, data) VALUES(?, ?)");
  stmt.bindText(1, "wildcat4.1_nullsroyale.rel.free_15.535.13_release");
  stmt.bindBlob(2, scriptBlob);
  stmt.step();
  db.close();

  console.log("cache test done");
};


// ==============================================================================================
// SECTION 7: BOOTSTRAP & HOOK ORCHESTRATOR (Module "B" / Function [32])
// ==============================================================================================

/**
 * Function [32]: Bootstrap & Hook Orchestrator ("B")
 * Bytecode offset: 0x14a9, cpool: [Function [24], [27], [28], [29], [30], [31]]
 *
 * Orchestrates detection of libg.so loading using a 3-tier cascade:
 *   - Tier 1: Hook `libc.so!__cxa_atexit` (called early by C++ static constructors)
 *   - Tier 2: Hook `libc.so!__cxa_atexit + 4` (if Tier 1 fails due to existing hooks)
 *   - Tier 3: Polling every 50ms (if hook installation fails completely)
 *
 * When libg.so is loaded:
 *   - Triggers network redirection [14]
 *   - Triggers GOT polyfills [22]
 *   - Applies ARM64 sigaction r-x permission fix [25]
 *
 * Schedules deferred script caching into SQLite after 15 seconds [31].
 */
var bootstrapOrchestrator = function() {
  console.log(Process.arch);

  var cxaAtexit = Module.findExportByName("libc.so", "__cxa_atexit");
  var atexitOpcodeWord = null;

  try {
    /**
     * Function [24]: Prologue code inspector
     * Bytecode offset: 0x1608, closure: [atexitOpcodeWord]
     */
    Memory.patchCode(cxaAtexit, Process.pointerSize, function(codePtr) {
      // (codePtr.readPointer() & 0xFFFFFFFF) >>> 16
      atexitOpcodeWord = codePtr.readPointer().and(4294967295.0).shr(16).toUInt32();
    });
  } catch (_) {}

  /**
   * Function [27]: Callback executed once libg.so is available in memory
   * Bytecode offset: 0x1655, closures: [atexitOpcodeWord, setupNetworkRedirection, installGotPolyfills]
   */
  var onLibgAvailable = function() {
    console.log("libg.so is available");

    // 1. Activate network redirection & in-memory review patches
    setupNetworkRedirection("royale.server.dnull.xyz"); // Function [14] ("E")

    // 2. Install GOT polyfills for missing libc symbols
    installGotPolyfills(); // Function [22] ("M")

    // 3. Apply platform-specific fixes
    $armv8_armv7(
      /**
       * Function [25]: ARM64 sigaction protection fix
       * Bytecode offset: 0x169b, closure: [atexitOpcodeWord]
       */
      function() {
        // 54531 == 0xD503 (NOP opcode in ARM64: 0xD503201F)
        if (atexitOpcodeWord === 54531) {
          var sigactionPtr = Module.findExportByName("libsigchain.so", "sigaction");
          if (sigactionPtr && !sigactionPtr.isNull()) {
            Memory.protect(sigactionPtr, 4, "r-x");
          }
        }
      },
      /**
       * Function [26]: ARM32 no-op stub
       * Bytecode offset: 0x1702
       */
      function() {
        return;
      }
    );
  };

  var isAttached = false;

  // --------------------------------------------------------------------------------------------
  // TIER 1: Interceptor on __cxa_atexit
  // --------------------------------------------------------------------------------------------
  try {
    /**
     * Function [28]: Tier 1 Hook Handler
     * Bytecode offset: 0x1714, closures: [hookTier1, isAttached, onLibgAvailable]
     */
    var hookTier1 = Interceptor.attach(cxaAtexit, function(args) {
      if (Module.findBaseAddress("libg.so")) {
        hookTier1.detach();
        if (!isAttached) {
          isAttached = true;
          onLibgAvailable();
        }
      }
    });
  } catch (_) {
    console.log("failed to set interceptor at JUMP_IN_PTR, trying to fall back to JUMP_IN_PTR + 4");

    // ------------------------------------------------------------------------------------------
    // TIER 2: Interceptor on __cxa_atexit + 4
    // ------------------------------------------------------------------------------------------
    try {
      /**
       * Function [29]: Tier 2 Hook Handler
       * Bytecode offset: 0x176b, closures: [hookTier2, isAttached, onLibgAvailable]
       */
      var hookTier2 = Interceptor.attach(cxaAtexit.add(4), function(args) {
        if (Module.findBaseAddress("libg.so")) {
          hookTier2.detach();
          if (!isAttached) {
            isAttached = true;
            onLibgAvailable();
          }
        }
      });
    } catch (_) {
      console.log("failed to set interceptor at JUMP_IN_PTR + 4, falling back to interval check");

      // ----------------------------------------------------------------------------------------
      // TIER 3: Polling interval every 50ms
      // ----------------------------------------------------------------------------------------
      /**
       * Function [30]: Tier 3 Interval Polling Handler
       * Bytecode offset: 0x17c2, closures: [intervalId, isAttached, onLibgAvailable]
       */
      var intervalId = setInterval(function() {
        if (Module.findBaseAddress("libg.so")) {
          clearInterval(intervalId);
          if (!isAttached) {
            isAttached = true;
            onLibgAvailable();
          }
        } else {
          console.log("interval check: libg.so is not available yet");
        }
      }, 50);
    }
  }

  // --------------------------------------------------------------------------------------------
  // DEFERRED CACHING: Save signed script to SQLite after 15 seconds
  // --------------------------------------------------------------------------------------------
  /**
   * Function [31]: 15-second deferred cache timer callback
   * Bytecode offset: 0x1823, closure: [cacheSignedScript]
   */
  setTimeout(function() {
    try {
      cacheSignedScript(); // Function [23] ("P")
    } catch (e) {
      console.log("test_cache_impl failed");
    }
  }, 15000);
};


// ==============================================================================================
// SECTION 8: CORE ENGINE MODULE WRAPPER (Module "w" / Function [33])
// ==============================================================================================

/**
 * Function [33]: Core Engine Module Definition
 * Bytecode offset: 0x0986, cpool: [Function [11], [14], [22], [23], [32]], closure: [__initStub]
 *
 * Bundles the 5 primary sub-modules and exports bootstrapOrchestrator [32].
 *
 * @param {Object} exports - Module exports object
 * @param {Object} module - Module container { exports: ... }
 */
var module_core_wrapper = function(exports, module) {
  var fn_v = patch_libg_review;          // Function [11] ("v")
  var fn_E = setupNetworkRedirection;    // Function [14] ("E")
  var fn_M = installGotPolyfills;         // Function [22] ("M")
  var fn_P = cacheSignedScript;           // Function [23] ("P")
  var fn_B = bootstrapOrchestrator;       // Function [32] ("B")

  __initStub(); // Function [4]

  var internalStateObj = {};
  var internalArray = [];

  // Export bootstrap orchestrator
  module.exports = fn_B;
};


// ==============================================================================================
// SECTION 9: NATIVE THREAD UNBLOCKING & ERROR REPORTING (Function [34])
// ==============================================================================================

/**
 * Function [34]: Native Thread Synchronizer ("I")
 * Bytecode offset: 0x1880
 *
 * Notifies `libwildcat.so` that JavaScript initialization has completed.
 * Calls native `wildcat_release_blocking(const char *errorString)`.
 * If an error occurred, passes the error message; otherwise passes NULL.
 *
 * @param {string|null} errMessage - Error message string, or null on success
 */
var wildcat_release_blocking = function(errMessage) {
  var fnPtr = Module.findExportByName("libwildcat.so", "wildcat_release_blocking");
  var fn = new NativeFunction(
    fnPtr,
    "int",
    ["pointer"],
    { exceptions: "propagate" }
  );

  if (errMessage != null) {
    var errUtf8 = Memory.allocUtf8String(errMessage);
    fn(errUtf8);
  } else {
    fn(NULL);
  }
};


// ==============================================================================================
// SECTION 10: MASTER BOOTSTRAP RUNNER & EXCEPTION HANDLER (Function [35])
// ==============================================================================================

/**
 * Function [35]: Master Runner ("L")
 * Bytecode offset: 0x1916, closures: [x, w, wildcat_release_blocking]
 *
 * Top-level executor invoked by the module entry point:
 *   1. Executes module "x" [7] (defines global.$arch and global.$armv8_armv7)
 *   2. Executes module "w" [33] and calls its exported bootstrap orchestrator [32]
 *   3. Catches any uncaught exceptions during setup
 *   4. Always calls `wildcat_release_blocking(errMsg)` [34] to unblock the waiting C++ thread
 */
var masterBootstrapRunner = function() {
  var errMsg = null;

  try {
    // 1. Initialize architecture helpers
    x(); // Function [7]

    // 2. Initialize core engine module and start bootstrap orchestrator
    // w() returns bootstrapOrchestrator [32], () executes it
    w()();
  } catch (err) {
    try {
      errMsg = err.message;
    } catch (_) {}
  }

  // 3. Unblock native C++ thread in libwildcat.so
  try {
    wildcat_release_blocking(errMsg); // Function [34]
  } catch (_) {}
};


// ==============================================================================================
// SECTION 11: ROOT MODULE ENTRY POINT (Function [36] / /cr-new-epoch.js)
// ==============================================================================================

/**
 * Function [36]: Root Module Orchestrator
 * Bytecode offset: 0x07a8, cpool: [Function [1], [3], [4], [7], [33], [34], [35]]
 *
 * Evaluated when `/cr-new-epoch.js` is loaded into QuickJS:
 *   - If invoked with `this` (object binding mode): attaches `I` and `L` to `this`.
 *   - Normal execution: instantiates module closures and triggers `masterBootstrapRunner()`.
 */
(function() {
  // If invoked with a 'this' context, bind lifecycle methods and exit
  if (this) {
    this.I = wildcat_release_blocking; // Function [34]
    this.L = masterBootstrapRunner;    // Function [35]
    return;
  }

  // 1. Register module lazy loaders
  var b = __commonJS; // Function [1]
  var u = __esm;      // Function [3]

  // 2. Wrap initialization stub
  var _ = b(__initStub); // Function [4]

  // 3. Wrap architecture helper module
  var x = u(module_architecture); // Function [7]

  // 4. Wrap core engine module
  var w = u(module_core_wrapper); // Function [33]

  // 5. Execute init
  _();

  // 6. Execute master bootstrap runner
  masterBootstrapRunner(); // Function [35]

  // 7. Return async resolution to QuickJS runtime
  return Promise.resolve();
})();
