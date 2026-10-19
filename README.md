# Null's Royale Client Loader Reverse Engineering

Technical summary of the protection mechanisms implemented in `libwildcat.so` and the injected QuickJS payload (`/cr-new-epoch.js` in `downloaded_script.qjsc`).

## Protection Architecture

The client modifies original Clash Royale binaries at runtime using an embedded Frida Core engine inside `libwildcat.so`. The protection relies on native thread synchronization, non-standard bytecode compilation, binary memory patching, and libc-level hooking.

### 1. Native Thread Blocking

`libwildcat.so` executes early during startup and suspends the main game thread. It initializes the QuickJS virtual machine and evaluates the decrypted payload. The game process remains blocked until the JavaScript engine explicitly calls the exported native function `wildcat_release_blocking`. If the script fails, an error message is forwarded to this call to abort execution.

### 2. Bytecode Obfuscation and Opcode Shift

Standard QuickJS tools crash when parsing `downloaded_script.qjsc` due to differences between serialized and internal opcode tables:

- **19-Opcode Shift**: The QuickJS compiler in Frida defines 267 opcodes but excludes 19 non-serializable instructions at index 182. Serialized opcodes 0 to 181 map 1:1 to runtime opcodes. Serialized opcodes 182 to 247 require adding 19 to align with runtime opcode indices.
- **Predefined Atom Table**: Atom identifiers below 228 reference a static null-delimited string table embedded in `libwildcat.so` at offset `0x3abff6`. The table is 1-indexed. Dynamic strings from the bytecode payload begin at index 228.

### 3. Early Engine Interception

The script must patch `libg.so` after it is mapped into memory but before game networking starts.

- **Trigger Point**: The loader hooks `__cxa_atexit` in `libc.so`, which executes during the invocation of `libg.so` static constructors in `.init_array`.
- **Fallback Chain**: If hooking the function entry fails, it attempts `__cxa_atexit + 4`. If both fail, it falls back to a 50 ms polling loop checking `Module.findBaseAddress("libg.so")`.
- **Prologue Analysis**: It inspects the first machine word of `__cxa_atexit` using `Memory.patchCode`. If the top 16 bits match value 54531 (ARM64 NOP opcode `0xD503`), the script restores memory protection of `sigaction` in `libsigchain.so` to read-execute.

### 4. Engine Code Patches

Once `libg.so` is detected, the script applies four direct memory modifications targeting UI text rendering and app rating popups:

- **Rich Text Formatting (`NativeFont::formatString`)**: Hooks offset `0x118D360` (ARM64) or `0xDA8D14` (ARM32) and writes `ptr(1)` into register `x4` or `r7` representing argument 5 (`char a5`). When set, `NativeFont::formatString` parses inline color tags (`<c#RRGGBB>...</c>`) and hex codes in chat messages and player names.
- **Text Animation Wrapper Replacement**: Replaces `sub_870F84` at offset `0x870F84` (ARM64) or `0x41A1CC` (ARM32) with `sub_11F07E0` at offset `0x11F07E0` (ARM64) or `0xE17DC8` (ARM32). Function `sub_870F84` applies animated text color flickering and randomized character transformations before calling `sub_11F07E0`. Replacing it forces immediate direct font glyph rendering using SIMD NEON instructions.
- **Rate App Dialog Suppression (`ShowRateAppDialog`)**: Replaces offset `0x75D1D4` (ARM64) or `0x2D88E8` (ARM32) with a stub returning zero and logging `bad review call`. The original function creates the store rating popup (`TID_RATE_APP_TITLE`, `TID_RATE_APP_MESSAGE`, `TID_BUTTON_RATE_APP_REVIEW`). The replacement prevents the client from attempting to open the Google Play store review flow.


### 5. Network Redirection

Redirection bypasses hardcoded game logic without modifying `.rodata` strings:

- **Hostname Resolution**: Hooks `getaddrinfo`. When the query targets `royale.server.dnull.xyz`, the script calls `wildcat_js_request("getHostnamePreference")` to fetch the active hostname and target port, then overwrites the string directly in the buffer pointed to by `args[0]`.
- **Port Rewriting**: Port 9339 is hardcoded in the compiled game code. The script intercepts `connect`, checks if `sin_port` in `struct sockaddr_in` equals 9339, and rewrites the field with the new port converted to big-endian using `htons`.

### 6. GOT Polyfills for Legacy Android Support

`libg.so` references newer Bionic symbols that are absent on older Android versions. The script iterates over Global Offset Table entries and writes replacement pointers if an entry contains null:

- `__cxa_thread_atexit_impl`: Replaced with an empty native callback.
- `__fwrite_chk`: Replaced with `fwrite` from `libc.so`.
- `__gnu_strerror_r`: Replaced with `strerror_r` from `libc.so`.
- `__register_atfork`: Replaced with an empty native callback.
- `stderr`: Replaced with `__sF + 0xA8` from `libc.so`.

### 7. SQLite Script Caching

Fifteen seconds after initialization, the script queries `wildcat_js_get_signed_script` and saves the binary payload into table `scripts` in `/wildcat.db` under key `wildcat4.1_nullsroyale.rel.free_15.535.13_release`.

## Repository Files

- `cr_new_epoch_decompiled.js`: Decompiled JavaScript payload containing all 37 functions.
- `downloaded_script.qjsc`: Raw compiled QuickJS module extracted from memory.
- `frida-quickjs-opcode.h`: Frida QuickJS opcode definition header.
- `scratch/`: Disassembly and stack emulation scripts used to reconstruct the bytecode.
