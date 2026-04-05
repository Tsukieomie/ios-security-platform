# iSH JIT Backend for TXM Devices (A17 Pro / iOS 26.5)

**Target audience:** Developer implementing a JIT backend for iSH on iPhone 15 Pro (A17 Pro, iOS 26.5) with SPTM + TXM active, no jailbreak.

**Revision date:** April 2026  
**Device:** iPhone 15 Pro — A17 Pro SoC — iOS 26.5  
**Constraint:** No jailbreak. No App Store distribution (sideloaded via SideStore). StikDebug used as debugger to satisfy TXM requirements.

---

## Table of Contents

1. [The TXM Memory Model — Exactly How It Works](#section-1)
2. [What Needs to Change in iSH](#section-2)
3. [JIT Memory Allocator — Exact Implementation](#section-3)
4. [x86→ARM64 Code Generator — Exact Implementation](#section-4)
5. [JIT Block Cache](#section-5)
6. [Integration with StikDebug — Startup Sequence](#section-6)
7. [x86 MMU Integration](#section-7)
8. [System Call Handling in JIT Code](#section-8)
9. [Lazy EFLAGS — Full Implementation](#section-9)
10. [Implementation Roadmap](#section-10)
11. [Key Risks and Mitigations](#section-11)
12. [Testing Strategy](#section-12)
13. [Sources](#sources)

---

<a name="section-1"></a>
## Section 1: The TXM Memory Model — Exactly How It Works

### 1.1 What TXM Is

TXM (Trusted Execution Monitor) was introduced on A15+ devices in iOS 17 alongside SPTM (Secure Page Table Monitor). Together they represent Apple's evolution from the Page Protection Layer (PPL) toward a microkernel-inspired compartmentalized architecture. The privilege hierarchy, from highest to lowest, is:

```
SPTM  (GL2 — Guarded Level 2, highest observed privilege)
  TXM (GL0 — handles code signing + entitlement enforcement)
    XNU kernel (EL1 — ARM Exception Level 1)
      Userland apps (EL0 — ARM Exception Level 0)
```

Guarded Levels (GLs) are Apple-proprietary lateral privilege domains introduced by the Guarded Execution Feature (GXF), operating alongside the standard ARM Exception Levels. They are enforced by Shadow Permissions Remapping Registers (SPRRs), which map page table entry bit patterns to different permissions per GL/EL combination. Entry into a GL is via the Apple-proprietary `GENTER` instruction (opcode `0x00201420`).

**SPTM** (GL2) is the sole authority for memory retyping and page table management. It enforces SPTM Domains:

| Domain | Contents |
|--------|----------|
| `SPTM_DOMAIN` | SPTM itself |
| `XNU_DOMAIN` | Standard XNU kernel operations |
| `TXM_DOMAIN` | Code signing, entitlement enforcement |
| `SK_DOMAIN` | Secure kernel (Exclaves) |

**TXM** (GL0) operates in its own isolated SPTM domain. XNU interacts with TXM via the `txm_kernel_call` interface, which routes through SPTM as intermediary. TXM validates code signing and entitlements for new executable mappings. Even a fully compromised XNU kernel cannot bypass TXM's validation because SPTM enforces memory isolation between domains at the hardware level.

### 1.2 W^X Enforcement at Hardware Level

On pre-A15 (PPL era), the Page Protection Layer ran in GL0 and protected page tables from XNU modification. Certain double-mapping tricks (mapping the same physical page twice — once PROT_WRITE, once PROT_EXEC, at two different virtual addresses) worked because the code signing check was a software enforcement in PPL that could be bypassed in some configurations.

On TXM/A17, any attempt to:

- Call `mprotect()` to make already-executable memory writable → results in `SIGKILL` from TXM
- Map the same physical page as both `PROT_WRITE` and `PROT_EXEC` via two virtual addresses without explicit TXM authorization → blocked at page table validation time
- Use `ptrace(PT_TRACE_ME)` alone to set `CS_DEBUGGED` and then map writable+executable pages → `CS_DEBUGGED` is set but TXM still validates the entitlement blob for new executable mappings with `MAP_JIT`

The key difference: on iOS 26.5 with TXM, `CS_DEBUGGED` alone is **not sufficient** for `MAP_JIT`. The `com.apple.security.cs.allow-jit` entitlement must be present in the signed entitlement blob, **and** a debugger must be actively attached.

### 1.3 The One Authorized Path for JIT on TXM Without a Jailbreak

Apple's official documentation (developer.apple.com/documentation/apple_silicon/porting_just-in-time_compilers_to_apple_silicon) defines a single authorized API surface for JIT on Apple Silicon with Hardened Runtime:

**`mmap(MAP_JIT)` + `pthread_jit_write_with_callback_np()` + `com.apple.security.cs.allow-jit` entitlement + `com.apple.security.cs.allow-jit-write-allowlist` entitlement**

This works because:

1. `MAP_JIT` tells TXM this virtual memory region is authorized for JIT use. TXM tracks this at the frame level via Frame Table Entries (FTEs).
2. `pthread_jit_write_with_callback_np()` atomically switches the **current thread's** permission on the JIT region: write-only → callback executes → execute-only. This is a per-thread permission managed by TXM via SPRR, not a global page table change. Other threads see the region as execute-only while one thread writes.
3. The callback must be registered in an allow-list via `PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP()` at compile time. The function verifies the callback is in this list before switching permissions. An unregistered callback causes an immediate crash.
4. The `com.apple.security.cs.allow-jit` entitlement must be present in the Mach-O entitlement blob, which TXM validates at process launch. Without it, `mmap(MAP_JIT)` returns `MAP_FAILED` with `errno = EPERM`.

### 1.4 iOS vs. macOS Differences for `allow-jit`

| Platform | Entitlement availability |
|----------|--------------------------|
| macOS | Grantable by Apple via App Store entitlements; used by Firefox, VSCode, Obsidian, Excel, etc. |
| iOS (App Store) | Reserved for Safari/WebKit via `com.apple.developer.web-browser-engine.rendering` + associated entitlements. Apple denied iSH's DMA interoperability request (September 2024) specifically citing that JIT for non-browser apps is out of scope. |
| iOS (dev-signed sideloaded) | A development certificate bypasses the App Store entitlement restriction check. `allow-jit` is validated differently for dev-signed apps — the signed entitlement blob is checked against the provisioning profile, not the App Store entitlement database. |

This is the loophole enabling iSH JIT without a jailbreak: sideload via SideStore with a development certificate, include `allow-jit` in the entitlement blob, use StikDebug to satisfy the debugger-attached requirement.

### 1.5 What the StikDebug Protocol Actually Does

StikDebug (github.com/StephenDev0/StikDebug) is an on-device debugger/JIT enabler for iOS 17.4+, powered by `idevice` (a Rust library for communicating with iOS devices over the lockdown protocol).

The mechanism:

1. StikDebug runs a local loopback VPN (LocalDevVPN) on the device. This creates a virtual network interface that routes traffic through `127.0.0.1`, enabling the lockdown service tunnel without a USB cable.
2. StikDebug communicates with the device's `lockdownd` and then `debugserver` via this loopback tunnel using the GDB Remote Serial Protocol (RSP).
3. When "Connect by App" is selected, StikDebug sends a `vAttach` RSP command targeting the iSH process PID. This is equivalent to Xcode's "Attach to Process" — it uses `PT_ATTACHEXC` (the XPC/Mach exception variant of ptrace attach) to attach `debugserver` to iSH.
4. Attaching sets the `CS_DEBUGGED` flag on the iSH process. This flag, combined with the `allow-jit` entitlement in the signed binary, satisfies TXM's requirement for `MAP_JIT` to succeed.
5. Once attached, `mmap(MAP_JIT, ...)` succeeds in the iSH process.

**Critical distinction for iOS 26.5 / TXM:** According to SideStore JIT documentation and community reports from the Amethyst/MeloNX teams, iOS 26 broke JIT for TXM-capable devices (A15+) in a way that requires apps to use `MAP_JIT` + `pthread_jit_write_with_callback_np()`. The older `shm_open` double-map technique no longer works on TXM devices. Only specifically-adapted apps (UTM, Amethyst, MeloNX, DolphiniOS) work on TXM as of December 2025 updates. iSH must be adapted to use the new API.

**Note on non-TXM fallback:** SideStore's built-in JIT enabler works on iOS 26 only for devices ~4+ years old (pre-A15, non-TXM). iPhone 15 Pro (A17) requires StikDebug.

---

<a name="section-2"></a>
## Section 2: What Needs to Change in iSH

### 2.1 Current iSH Interpreter (Asbestos) — How It Works

iSH's interpreter is named Asbestos ("long-term exposure to this code may cause loss of sanity"). It is a **threaded code interpreter**, not a JIT. The execution model:

1. iSH reads x86 machine code bytes from the emulated process's guest memory.
2. The x86 decoder translates each instruction into an array of **gadgets** — pre-compiled ARM64 function pointers baked into the iSH binary at build time.
3. Each gadget is a small function implementing one semantic operation (e.g., "add eax, ecx"). It ends with a tail-call to the next gadget pointer in the array.
4. This is equivalent to Forth's direct threading: execution flows through a pre-computed chain of function pointers.
5. The gadget functions are written largely in ARM64 assembly, compiled and signed by Apple at build time. **No new executable code is ever generated at runtime.**
6. This design gives Asbestos a 3–5x speedup over a simple switch-dispatch interpreter (per the iSH README), but leaves enormous performance on the table compared to true JIT.
7. iSH currently benchmarks **5–100x slower than native** depending on workload (per the iSH blog post on JIT and the EU DMA).

The App Store accepts iSH because Asbestos generates no new executable code — it only dispatches through pre-signed gadgets. The JIT upgrade changes this fundamentally.

### 2.2 The iSH Source Tree — What to Touch

The repository layout (from github.com/ish-app/ish):

```
ish/
├── asbestos/       ← Asbestos gadget assembly — DO NOT MODIFY for JIT
├── emu/
│   ├── cpu.h       ← CPU state struct (registers, flags, segment descriptors)
│   ├── mmu.h       ← MMU interface (guest virtual → host pointer translation)
│   ├── tlb.c       ← TLB caching recent address translations
│   ├── fpu.c       ← x87 FPU emulation
│   ├── vec.c       ← SSE/SSE2 vector emulation
│   └── mmx.c       ← MMX emulation
├── kernel/
│   └── calls.c     ← Syscall dispatch (handle_interrupt at line 490)
├── app/
│   └── AppDelegate.m ← iOS app lifecycle — add JIT init here
└── iSH.entitlements  ← ADD JIT ENTITLEMENTS HERE
```

**New files to create:**

```
emu/
├── jit.h           ← JIT public interface declarations
├── jit.c           ← JIT region allocator + block cache + TXM-compliant mmap
├── jit_arm64.h     ← ARM64 encoding helpers and register definitions
├── jit_arm64.c     ← x86→ARM64 translator (main translation engine)
└── jit_eflags.c    ← Lazy EFLAGS computation
```

**Files to modify:**

```
emu/cpu.h           ← Add jit_block* pointer to cpu_state for hot-path block caching
app/AppDelegate.m   ← Add StikDebug timing logic + jit_init() call
iSH.entitlements    ← Add 5 new entitlement keys (see Section 3a)
meson.build         ← Add new emu/jit*.c source files
```

### 2.3 Execution Path After JIT Integration

```
x86 guest PC (EIP)
        |
        v
[jit_cache_lookup(eip)]
        |
   HIT  |  MISS
        |    |
        |    v
        |  [jit_translate_block(cpu, eip)]
        |    |-- decode x86 instructions until branch/call/ret
        |    |-- for each instruction: translate to ARM64 or emit_interpreter_fallback()
        |    |-- jit_emit() → pthread_jit_write_with_callback_np() → sys_icache_invalidate()
        |    |-- jit_cache_insert(block)
        |
        v
[block->host_ptr](cpu)     ← call ARM64 code in MAP_JIT region
        |
        v
ARM64 epilogue: update cpu->eip, return to jit_execute()
        |
        v
Loop back to jit_cache_lookup()
```

---

<a name="section-3"></a>
## Section 3: JIT Memory Allocator — Exact Implementation

### 3a. Required Entitlements

Modify `iSH.entitlements` to add:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- EXISTING iSH ENTITLEMENTS (keep as-is) -->
    <!-- ... -->

    <!-- ===== JIT ENTITLEMENTS — ALL REQUIRED FOR TXM JIT ===== -->

    <!-- Enables mmap(MAP_JIT) on TXM devices when debugger is attached.
         On iOS, this is dev-certificate-only (not App Store grantable).
         Apple denied DMA request for non-browser JIT in September 2024. -->
    <key>com.apple.security.cs.allow-jit</key>
    <true/>

    <!-- Enables the callback allowlist mechanism via PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP.
         Without this, pthread_jit_write_with_callback_np() is not available.
         This is the NEW API required for TXM — the old pthread_jit_write_protect_np()
         is macOS-only and is NOT available on iOS. -->
    <key>com.apple.security.cs.allow-jit-write-allowlist</key>
    <true/>

    <!-- Allows an external debugger (StikDebug/debugserver) to attach.
         This sets CS_DEBUGGED on the process, which combined with allow-jit
         satisfies TXM's requirement for MAP_JIT to succeed.
         Without this, StikDebug cannot attach and MAP_JIT will fail. -->
    <key>get-task-allow</key>
    <true/>

    <!-- PERFORMANCE: Allows the app to request a larger memory limit.
         The JIT code cache (64MB) plus the existing iSH heap requires headroom.
         This does not guarantee the limit; it signals intent to the kernel. -->
    <key>com.apple.developer.kernel.increased-memory-limit</key>
    <true/>

    <!-- PERFORMANCE: Extended virtual address space.
         Gives more VA space for JIT region + guest memory + host memory.
         Required on 32-bit iOS builds where VA space is limited. -->
    <key>com.apple.developer.kernel.extended-virtual-addressing</key>
    <true/>
</dict>
</plist>
```

**Provisioning profile requirement:** The development provisioning profile must be created on developer.apple.com with these entitlements explicitly listed. Xcode's automatic signing may strip unknown entitlements. Use manual signing with a custom `.entitlements` file and verify with:

```bash
codesign -d --entitlements - /path/to/iSH.app
```

### 3b. `emu/jit.h` — Public Interface

```c
// emu/jit.h — JIT public interface for iSH
// TXM-compliant JIT for iPhone 15 Pro (A17 Pro), iOS 26.5
// © iSH project — see LICENSE.md

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "cpu.h"

// Opaque JIT block handle
typedef struct jit_block jit_block_t;

// -----------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------

// Initialize the JIT subsystem. Must be called AFTER StikDebug attaches.
// Returns 0 on success, -1 if MAP_JIT fails (debugger not attached,
// or TXM blocked — will automatically fall back to Asbestos interpreter).
int jit_init(void);

// Tear down JIT region and free block cache. Call at app exit.
void jit_destroy(void);

// True if JIT was successfully initialized.
bool jit_is_available(void);

// -----------------------------------------------------------------------
// Block translation + execution
// -----------------------------------------------------------------------

// Look up a translated block by guest x86 EIP.
// Returns NULL if block not in cache (must translate).
jit_block_t *jit_cache_lookup(uint32_t guest_eip);

// Translate a basic block starting at guest_eip.
// Decodes x86 from cpu->mem, generates ARM64 into JIT region.
// Returns translated block on success, NULL on failure.
jit_block_t *jit_translate_block(struct cpu_state *cpu, uint32_t guest_eip);

// Insert a translated block into the cache.
void jit_cache_insert(jit_block_t *block);

// Invalidate all cached blocks (e.g., when guest writes to code pages).
void jit_cache_flush_all(void);

// Invalidate blocks covering a specific guest address range.
// Call when iSH's MMU detects a write to a mapped executable page.
void jit_cache_invalidate_range(uint32_t guest_start, uint32_t guest_end);

// Main JIT execution loop — replaces Asbestos dispatch.
// Runs until cpu->exit_requested is set.
void jit_execute(struct cpu_state *cpu);

// -----------------------------------------------------------------------
// Low-level emit (used by jit_arm64.c)
// -----------------------------------------------------------------------

// Write ARM64 instructions into JIT region via TXM-compliant callback.
// Returns pointer to executable ARM64 code on success, NULL on failure.
// Handles pthread_jit_write_with_callback_np + sys_icache_invalidate internally.
void *jit_emit(const uint32_t *arm64_insns, size_t insn_count);
```

### 3c. `emu/jit.c` — Full Implementation

```c
// emu/jit.c — TXM-compliant JIT memory allocator and block cache for iSH
// Target: iPhone 15 Pro (A17 Pro), iOS 26.5, SPTM + TXM active
//
// REQUIREMENTS:
//   - com.apple.security.cs.allow-jit in iSH.entitlements
//   - com.apple.security.cs.allow-jit-write-allowlist in iSH.entitlements
//   - get-task-allow in iSH.entitlements
//   - StikDebug attached as debugger before jit_init() is called
//
// API REFERENCE:
//   pthread_jit_write_with_callback_np: sys/mman.h (private, available dev cert only)
//   PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP: pthread.h extension
//   sys_icache_invalidate: libkern/OSCacheControl.h
//   MAP_JIT: sys/mman.h

#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <libkern/OSCacheControl.h>
#include "jit.h"
#include "cpu.h"

// -----------------------------------------------------------------------
// Configuration constants
// -----------------------------------------------------------------------

// 64 MB JIT code region. One region per process (MAP_JIT limitation on iOS).
// This is enough for ~16 million ARM64 instructions of cached JIT code.
// The 64MB figure leaves headroom given com.apple.developer.kernel.increased-memory-limit.
#define JIT_CACHE_SIZE          (64 * 1024 * 1024)

// Maximum ARM64 bytes for a single translated x86 basic block.
// A basic block is typically 5-50 x86 instructions; at worst-case expansion
// (each x86 → ~8 ARM64), 500 instructions × 8 × 4 bytes = 16KB. 32KB is safe.
#define JIT_BLOCK_MAX_BYTES     (32768)

// Hash table size for block cache. Power of 2 for fast modulo via masking.
// 65536 entries × 24 bytes/entry = 1.5 MB resident — acceptable.
#define JIT_HASH_BUCKETS        (1 << 16)
#define JIT_HASH_MASK           (JIT_HASH_BUCKETS - 1)

// -----------------------------------------------------------------------
// JIT block structure
// -----------------------------------------------------------------------

struct jit_block {
    uint32_t guest_eip;       // x86 guest address this block starts at (hash key)
    void     *host_ptr;       // Pointer into JIT region — executable ARM64 code
    size_t    host_size;      // Byte count of ARM64 code
    uint32_t  guest_end_eip;  // First guest address AFTER this block (for range invalidation)
    struct jit_block *next;   // Hash chain (separate chaining)
};

// -----------------------------------------------------------------------
// Module state
// -----------------------------------------------------------------------

// The single MAP_JIT region — allocated once in jit_init()
static void         *g_jit_region   = NULL;
static size_t        g_jit_used     = 0;
static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;

// Block cache — hash table with separate chaining
static struct jit_block *g_cache[JIT_HASH_BUCKETS];
static pthread_mutex_t   g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

// Block pool — pre-allocated to avoid malloc() on hot path
#define BLOCK_POOL_SIZE  65536
static struct jit_block  g_block_pool[BLOCK_POOL_SIZE];
static int               g_pool_head = 0;
static pthread_mutex_t   g_pool_lock = PTHREAD_MUTEX_INITIALIZER;

static bool g_jit_available = false;

// -----------------------------------------------------------------------
// Callback allow-list registration — MUST appear exactly once in the executable.
// This macro registers jit_write_callback with the allow-list that
// pthread_jit_write_with_callback_np() validates before switching thread permissions.
// Placing this in a .c file that is compiled into the main executable is correct.
// Do NOT place this in a dynamic library — iOS does not support the freeze-late variant.
// -----------------------------------------------------------------------

// Forward declaration required before PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP
static int jit_write_callback(void *ctx);

PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP(jit_write_callback);

// -----------------------------------------------------------------------
// Write context — passed through the callback to do the actual memcpy
// -----------------------------------------------------------------------

typedef struct {
    void       *dest;   // Destination address in JIT region
    const void *src;    // Source: ARM64 instructions to copy
    size_t      size;   // Byte count
} jit_write_ctx_t;

// This callback runs with the JIT region mapped WRITE (not executable) for this thread.
// Any code in this function that accesses the JIT region will see it as writable.
// The callback must NOT call pthread_jit_write_with_callback_np() recursively.
static int jit_write_callback(void *ctx_raw) {
    jit_write_ctx_t *ctx = (jit_write_ctx_t *)ctx_raw;
    // memcpy is safe here: dest is in the JIT region (writable for this thread)
    memcpy(ctx->dest, ctx->src, ctx->size);
    return 0;  // Return value propagated back to jit_emit caller
}

// -----------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------

int jit_init(void) {
    // mmap(MAP_JIT) requirements on A17/iOS 26.5:
    //   1. com.apple.security.cs.allow-jit in entitlement blob (verified by TXM at launch)
    //   2. Active debugger attachment (CS_DEBUGGED flag set by StikDebug)
    //   3. Only one MAP_JIT region per process is supported on iOS with Hardened Runtime
    //
    // Protection flags: PROT_READ | PROT_EXEC initially.
    // Write permissions are granted per-thread via pthread_jit_write_with_callback_np.
    // DO NOT use PROT_WRITE here — TXM will block execution of the region if
    // the initial mapping includes PROT_WRITE.

    g_jit_region = mmap(
        NULL,                           // Let kernel choose VA
        JIT_CACHE_SIZE,
        PROT_READ | PROT_EXEC,          // RX: TXM-approved initial state
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
        -1,                             // No file descriptor
        0                               // No offset
    );

    if (g_jit_region == MAP_FAILED) {
        g_jit_region = NULL;
        int err = errno;
        fprintf(stderr,
            "[iSH-JIT] mmap(MAP_JIT) failed: %s (errno=%d)\n"
            "[iSH-JIT] Checklist:\n"
            "[iSH-JIT]   1. Is com.apple.security.cs.allow-jit in iSH.entitlements?\n"
            "[iSH-JIT]   2. Is iSH signed with a development certificate?\n"
            "[iSH-JIT]   3. Has StikDebug been attached (CS_DEBUGGED set)?\n"
            "[iSH-JIT]   4. iOS 26.5 — TXM requires all three conditions.\n"
            "[iSH-JIT] Falling back to Asbestos interpreter.\n",
            strerror(err), err);
        return -1;
    }

    g_jit_used = 0;
    g_jit_available = true;
    memset(g_cache, 0, sizeof(g_cache));
    memset(g_block_pool, 0, sizeof(g_block_pool));
    g_pool_head = 0;

    fprintf(stderr,
        "[iSH-JIT] Initialized: region=%p size=%zu MB\n",
        g_jit_region, JIT_CACHE_SIZE / (1024 * 1024));

    return 0;
}

void jit_destroy(void) {
    if (g_jit_region) {
        munmap(g_jit_region, JIT_CACHE_SIZE);
        g_jit_region = NULL;
    }
    g_jit_available = false;
}

bool jit_is_available(void) {
    return g_jit_available;
}

// -----------------------------------------------------------------------
// Block pool allocator — O(1), no malloc on hot path
// -----------------------------------------------------------------------

static struct jit_block *pool_alloc(void) {
    pthread_mutex_lock(&g_pool_lock);
    if (g_pool_head >= BLOCK_POOL_SIZE) {
        // Pool exhausted — wrap. This invalidates all pool-allocated blocks.
        // A real implementation would use a proper freelist; this is phase-1 quality.
        g_pool_head = 0;
        jit_cache_flush_all();
    }
    struct jit_block *b = &g_block_pool[g_pool_head++];
    pthread_mutex_unlock(&g_pool_lock);
    memset(b, 0, sizeof(*b));
    return b;
}

// -----------------------------------------------------------------------
// JIT region bump allocator
// -----------------------------------------------------------------------

// Emit ARM64 instructions into the JIT region.
// Internally calls pthread_jit_write_with_callback_np — TXM mediates the write.
// Returns pointer to executable code, NULL on failure.
void *jit_emit(const uint32_t *arm64_insns, size_t insn_count) {
    size_t size = insn_count * sizeof(uint32_t);

    if (!g_jit_region || size == 0 || size > JIT_BLOCK_MAX_BYTES)
        return NULL;

    pthread_mutex_lock(&g_alloc_lock);

    // If we'd overflow the region, wrap back to the beginning.
    // This invalidates all cached blocks — they point into stale JIT memory.
    if (g_jit_used + size > JIT_CACHE_SIZE) {
        g_jit_used = 0;
        jit_cache_flush_all();
    }

    void *dest = (uint8_t *)g_jit_region + g_jit_used;

    // TXM-compliant write:
    //   1. pthread_jit_write_with_callback_np checks jit_write_callback is in allow-list
    //   2. Makes g_jit_region WRITE (not EXEC) for this thread via SPRR/TXM
    //   3. Calls jit_write_callback — memcpy executes
    //   4. Makes g_jit_region EXEC (not WRITE) for this thread via SPRR/TXM
    //   5. Returns jit_write_callback's return value (0 = success)
    jit_write_ctx_t ctx = { .dest = dest, .src = arm64_insns, .size = size };
    int rc = pthread_jit_write_with_callback_np(jit_write_callback, &ctx);

    if (rc != 0) {
        pthread_mutex_unlock(&g_alloc_lock);
        fprintf(stderr, "[iSH-JIT] jit_write_callback failed: rc=%d\n", rc);
        return NULL;
    }

    // MANDATORY on Apple Silicon: The data cache and instruction cache are
    // NOT coherent on ARM. Written bytes are in the D-cache; the I-cache
    // still holds whatever was there before (or is empty). The CPU will
    // execute I-cache content. Failing to call sys_icache_invalidate() here
    // results in executing garbage/stale instructions — the hardest class of
    // bug to debug because it manifests as seemingly random crashes or wrong results.
    sys_icache_invalidate(dest, size);

    // Advance bump pointer, aligned to 16 bytes (AArch64 stack alignment requirement
    // and cache line friendliness).
    g_jit_used += size;
    g_jit_used = (g_jit_used + 15) & ~(size_t)15;

    pthread_mutex_unlock(&g_alloc_lock);
    return dest;
}

// -----------------------------------------------------------------------
// Block cache — hash table with separate chaining
// -----------------------------------------------------------------------

// Knuth multiplicative hash for 32-bit guest EIP → bucket index
static inline uint32_t hash_eip(uint32_t eip) {
    return ((eip * 2654435761u) >> 16) & JIT_HASH_MASK;
}

jit_block_t *jit_cache_lookup(uint32_t guest_eip) {
    uint32_t bucket = hash_eip(guest_eip);
    // No lock here: lookup is on the hot path. Cache insertions are atomic
    // (pointer store). False misses are safe — they just retrigger translation.
    // False hits from torn pointer reads are not possible on ARM64 (aligned
    // 64-bit pointer stores are atomic per the ARM memory model).
    for (struct jit_block *b = g_cache[bucket]; b != NULL; b = b->next) {
        if (b->guest_eip == guest_eip)
            return b;
    }
    return NULL;
}

void jit_cache_insert(jit_block_t *block) {
    uint32_t bucket = hash_eip(block->guest_eip);
    pthread_mutex_lock(&g_cache_lock);
    block->next = g_cache[bucket];
    // Atomic store: other threads doing lockless lookup will either see the
    // old chain (miss, retrigger translation) or the new block. Both are safe.
    __atomic_store_n(&g_cache[bucket], block, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_cache_lock);
}

void jit_cache_flush_all(void) {
    pthread_mutex_lock(&g_cache_lock);
    memset(g_cache, 0, sizeof(g_cache));
    // Block pool reset happens at the allocator level
    pthread_mutex_unlock(&g_cache_lock);
}

void jit_cache_invalidate_range(uint32_t guest_start, uint32_t guest_end) {
    // Walk all buckets — O(n) but called rarely (only on self-modifying code).
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < JIT_HASH_BUCKETS; i++) {
        struct jit_block **pp = &g_cache[i];
        while (*pp) {
            struct jit_block *b = *pp;
            // Invalidate if block overlaps the written guest range
            if (b->guest_eip < guest_end && b->guest_end_eip > guest_start) {
                *pp = b->next;  // Unlink
                // Note: b itself remains in the pool but is now unreachable
                // from the cache. Next pool wrap will reclaim it.
            } else {
                pp = &b->next;
            }
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
}

// -----------------------------------------------------------------------
// Main execution loop
// -----------------------------------------------------------------------

void jit_execute(struct cpu_state *cpu) {
    while (!cpu->exit_requested) {
        uint32_t eip = cpu->eip;

        struct jit_block *block = jit_cache_lookup(eip);

        if (block == NULL) {
            block = jit_translate_block(cpu, eip);
            if (block == NULL) {
                // Translation failed (e.g., unknown instruction, memory fault).
                // Fall back to Asbestos for one instruction and retry.
                // asbestos_interpret_one() is the existing iSH interpreter entry.
                extern void asbestos_interpret_one(struct cpu_state *cpu);
                asbestos_interpret_one(cpu);
                continue;
            }
            jit_cache_insert(block);
        }

        // Execute the translated ARM64 code.
        // The JIT block receives cpu as its only argument (x0) and returns when
        // the basic block ends (branch, call, ret, or block-length limit).
        // It updates cpu->eip before returning.
        typedef void (*jit_func_t)(struct cpu_state *);
        jit_func_t fn = (jit_func_t)block->host_ptr;
        fn(cpu);

        // cpu->eip has been updated by the ARM64 epilogue in the JIT block.
    }
}
```

---

<a name="section-4"></a>
## Section 4: x86→ARM64 Code Generator — Exact Implementation

### 4a. Architecture of the Code Generator

The generator operates at the **basic block** level. A basic block is a maximal straight-line sequence of instructions with no branches into the middle. Ends when the x86 decoder encounters:

- An unconditional branch: `JMP rel8`, `JMP rel32`, `JMP r/m32`
- A conditional branch: `Jcc rel8`, `Jcc rel32`
- A function call: `CALL rel32`, `CALL r/m32`
- A return: `RET`, `RETN`, `RETF`
- An interrupt: `INT n`, `INTO`, `SYSCALL`
- Block size limit: more than 128 x86 instructions in one block (prevents pathological cases)

Each translated block:
1. Begins with a **prologue** that loads the CPU state pointer into `x19`.
2. Translates each x86 instruction sequentially.
3. Ends with an **epilogue** that stores the updated `cpu->eip` and returns to `jit_execute()`.

### 4b. ARM64 Register Allocation

ARM64 has 31 general-purpose 64-bit registers (x0–x30). Registers x19–x28 are callee-saved (must be preserved across function calls). We dedicate callee-saved registers to the x86 state that appears most frequently:

```c
// emu/jit_arm64.h — Register mapping and ARM64 encoding helpers

#pragma once
#include <stdint.h>

// -----------------------------------------------------------------------
// Dedicated register map
// -----------------------------------------------------------------------
// x19 — pointer to struct cpu_state (never changes within a JIT block)
#define ARM_REG_CPU     19

// x86 GPR → ARM64 register mapping (callee-saved: x20-x28)
// These hold the LIVE value of the x86 register while inside a JIT block.
// On block entry (prologue), they are loaded from cpu_state.
// On block exit (epilogue), they are flushed back to cpu_state.
#define ARM_REG_EAX     20   // x20 ← cpu->eax
#define ARM_REG_ECX     21   // x21 ← cpu->ecx
#define ARM_REG_EDX     22   // x22 ← cpu->edx
#define ARM_REG_EBX     23   // x23 ← cpu->ebx
#define ARM_REG_ESP     24   // x24 ← cpu->esp
#define ARM_REG_EBP     25   // x25 ← cpu->ebp
#define ARM_REG_ESI     26   // x26 ← cpu->esi
#define ARM_REG_EDI     27   // x27 ← cpu->edi

// Scratch registers — caller-saved, used for temporaries within instruction translation.
// Safe to clobber without save/restore.
#define ARM_REG_TMP0     0   // x0  — also used for function call arguments
#define ARM_REG_TMP1     1   // x1
#define ARM_REG_TMP2     2   // x2
#define ARM_REG_TMP3     3   // x3
#define ARM_REG_TMP4     4   // x4

// Link register (used by BL/RET)
#define ARM_REG_LR      30   // x30

// Zero register (reads as 0, writes discarded)
#define ARM_REG_XZR     31

// Map x86 register index (0=EAX, 1=ECX, ..., 7=EDI) to ARM64 register
static const int x86_to_arm_reg[8] = {
    ARM_REG_EAX,  // 0 = EAX
    ARM_REG_ECX,  // 1 = ECX
    ARM_REG_EDX,  // 2 = EDX
    ARM_REG_EBX,  // 3 = EBX
    ARM_REG_ESP,  // 4 = ESP
    ARM_REG_EBP,  // 5 = EBP
    ARM_REG_ESI,  // 6 = ESI
    ARM_REG_EDI,  // 7 = EDI
};
```

### 4c. ARM64 Instruction Encoding Helpers

ARM64 uses 32-bit fixed-width little-endian instructions. All encoding helpers produce a `uint32_t`.

```c
// emu/jit_arm64.h (continued) — instruction encoders

// -----------------------------------------------------------------------
// MOV / MOVZ / MOVK — immediate loads
// -----------------------------------------------------------------------

// MOV Xd, Xn  (alias: ORR Xd, XZR, Xn)
static inline uint32_t arm64_mov_reg(int rd, int rn) {
    // ORR (shifted register): sf=1, opc=01, shift=00, N=0, Rm=rn, imm6=0, Rn=XZR, Rd=rd
    return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}

// MOV Wd, Wn  (32-bit register move, zero-extends to 64)
static inline uint32_t arm64_mov_reg32(int rd, int rn) {
    return 0x2A0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}

// MOVZ Xd, #imm16, LSL #shift  (shift: 0, 16, 32, 48)
// Zero-fills other bits. Use for first 16-bit chunk of a large immediate.
static inline uint32_t arm64_movz(int rd, uint16_t imm, int shift_bits) {
    uint32_t hw = (uint32_t)(shift_bits / 16) & 3;
    return 0xD2800000u | (hw << 21) | ((uint32_t)imm << 5) | (uint32_t)rd;
}

// MOVZ Wd, #imm16  (32-bit variant, hw=0 only)
static inline uint32_t arm64_movz32(int rd, uint16_t imm) {
    return 0x52800000u | ((uint32_t)imm << 5) | (uint32_t)rd;
}

// MOVK Xd, #imm16, LSL #shift  (keep other bits, insert this chunk)
static inline uint32_t arm64_movk(int rd, uint16_t imm, int shift_bits) {
    uint32_t hw = (uint32_t)(shift_bits / 16) & 3;
    return 0xF2800000u | (hw << 21) | ((uint32_t)imm << 5) | (uint32_t)rd;
}

// Emit the minimal instruction sequence to load a 32-bit immediate into Xd.
// Writes into buf[], returns number of instructions emitted (1 or 2).
static inline int arm64_load_imm32(uint32_t *buf, int rd, uint32_t imm) {
    if (imm >> 16 == 0) {
        // Fits in 16 bits: one MOVZ
        buf[0] = arm64_movz32(rd, (uint16_t)imm);
        return 1;
    }
    // Two instructions: MOVZ (low 16) + MOVK (high 16)
    buf[0] = arm64_movz32(rd, (uint16_t)(imm & 0xFFFF));
    buf[1] = arm64_movk(rd, (uint16_t)(imm >> 16), 16);
    return 2;
}

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------

// ADD Xd, Xn, Xm  (64-bit)
static inline uint32_t arm64_add_reg(int rd, int rn, int rm) {
    return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADD Wd, Wn, Wm  (32-bit, zero-extends result)
static inline uint32_t arm64_add_reg32(int rd, int rn, int rm) {
    return 0x0B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADDS Wd, Wn, Wm  (32-bit, sets NZCV flags)
static inline uint32_t arm64_adds_reg32(int rd, int rn, int rm) {
    return 0x2B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADD Xd, Xn, #imm12 (unsigned immediate, 0..4095)
static inline uint32_t arm64_add_imm(int rd, int rn, uint16_t imm12) {
    return 0x91000000u | ((uint32_t)(imm12 & 0xFFF) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADD Wd, Wn, #imm12 (32-bit immediate)
static inline uint32_t arm64_add_imm32(int rd, int rn, uint16_t imm12) {
    return 0x11000000u | ((uint32_t)(imm12 & 0xFFF) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Xd, Xn, Xm
static inline uint32_t arm64_sub_reg(int rd, int rn, int rm) {
    return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Wd, Wn, Wm
static inline uint32_t arm64_sub_reg32(int rd, int rn, int rm) {
    return 0x4B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUBS Wd, Wn, Wm  (sets NZCV flags — used for CMP when discarding result)
static inline uint32_t arm64_subs_reg32(int rd, int rn, int rm) {
    return 0x6B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Xd, Xn, #imm12
static inline uint32_t arm64_sub_imm(int rd, int rn, uint16_t imm12) {
    return 0xD1000000u | ((uint32_t)(imm12 & 0xFFF) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Wd, Wn, #imm12
static inline uint32_t arm64_sub_imm32(int rd, int rn, uint16_t imm12) {
    return 0x51000000u | ((uint32_t)(imm12 & 0xFFF) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// -----------------------------------------------------------------------
// Logical
// -----------------------------------------------------------------------

// AND Wd, Wn, Wm
static inline uint32_t arm64_and_reg32(int rd, int rn, int rm) {
    return 0x0A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ORR Wd, Wn, Wm
static inline uint32_t arm64_orr_reg32(int rd, int rn, int rm) {
    return 0x2A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// EOR Wd, Wn, Wm
static inline uint32_t arm64_eor_reg32(int rd, int rn, int rm) {
    return 0x4A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ANDS Wd, Wn, Wm  (sets NZCV.NZ, clears VC — for x86 TEST/AND flag semantics)
static inline uint32_t arm64_ands_reg32(int rd, int rn, int rm) {
    return 0x6A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// MVN Wd, Wm  (bitwise NOT)
static inline uint32_t arm64_mvn_reg32(int rd, int rm) {
    return 0x2A2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}

// LSL Wd, Wn, Wm  (logical shift left by register)
static inline uint32_t arm64_lsl_reg32(int rd, int rn, int rm) {
    return 0x1AC02000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// LSR Wd, Wn, Wm  (logical shift right by register)
static inline uint32_t arm64_lsr_reg32(int rd, int rn, int rm) {
    return 0x1AC02400u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ASR Wd, Wn, Wm  (arithmetic shift right by register)
static inline uint32_t arm64_asr_reg32(int rd, int rn, int rm) {
    return 0x1AC02800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// -----------------------------------------------------------------------
// Memory access
// -----------------------------------------------------------------------

// LDR Xd, [Xn, #imm12]  (64-bit load, imm12 scaled by 8, range 0..32760)
static inline uint32_t arm64_ldr64(int rd, int rn, uint16_t imm12) {
    return 0xF9400000u | ((uint32_t)(imm12/8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// LDR Wd, [Xn, #imm12]  (32-bit load, imm12 scaled by 4, range 0..16380)
static inline uint32_t arm64_ldr32(int rd, int rn, uint16_t imm12) {
    return 0xB9400000u | ((uint32_t)(imm12/4) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STR Xd, [Xn, #imm12]
static inline uint32_t arm64_str64(int rd, int rn, uint16_t imm12) {
    return 0xF9000000u | ((uint32_t)(imm12/8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STR Wd, [Xn, #imm12]
static inline uint32_t arm64_str32(int rd, int rn, uint16_t imm12) {
    return 0xB9000000u | ((uint32_t)(imm12/4) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// LDR Wd, [Xn, Xm]  (register offset, 32-bit load)
static inline uint32_t arm64_ldr32_reg(int rd, int rn, int rm) {
    return 0xB8606800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STR Wd, [Xn, Xm]
static inline uint32_t arm64_str32_reg(int rd, int rn, int rm) {
    return 0xB8206800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STP Xn, Xm, [Xd, #imm7]!  (store pair + pre-index, used for callee-save)
// imm7 is scaled by 8, range -512..504
static inline uint32_t arm64_stp_preindex(int rn, int rm, int rd, int16_t imm7) {
    uint32_t imm = (uint32_t)((imm7 / 8) & 0x7F);
    return 0xA9800000u | (imm << 15) | ((uint32_t)rm << 10) | ((uint32_t)rd << 5) | (uint32_t)rn;
}

// LDP Xn, Xm, [Xd], #imm7  (load pair + post-index)
static inline uint32_t arm64_ldp_postindex(int rn, int rm, int rd, int16_t imm7) {
    uint32_t imm = (uint32_t)((imm7 / 8) & 0x7F);
    return 0xA8C00000u | (imm << 15) | ((uint32_t)rm << 10) | ((uint32_t)rd << 5) | (uint32_t)rn;
}

// -----------------------------------------------------------------------
// Branch
// -----------------------------------------------------------------------

// B #offset  (unconditional branch, offset in INSTRUCTIONS, range ±128MB)
static inline uint32_t arm64_b(int32_t insn_offset) {
    return 0x14000000u | ((uint32_t)insn_offset & 0x3FFFFFFu);
}

// BL #offset  (branch with link, for helper calls)
static inline uint32_t arm64_bl(int32_t insn_offset) {
    return 0x94000000u | ((uint32_t)insn_offset & 0x3FFFFFFu);
}

// BLR Xn  (branch with link to register — for indirect calls)
static inline uint32_t arm64_blr(int rn) {
    return 0xD63F0000u | ((uint32_t)rn << 5);
}

// BR Xn  (branch to register — for indirect jumps)
static inline uint32_t arm64_br(int rn) {
    return 0xD61F0000u | ((uint32_t)rn << 5);
}

// RET  (return via x30)
static inline uint32_t arm64_ret(void) {
    return 0xD65F03C0u;
}

// Bcc #offset  (conditional branch, offset in instructions, range ±1MB)
// cond: 0=EQ, 1=NE, 2=CS/HS, 3=CC/LO, 4=MI, 5=PL, 6=VS, 7=VC,
//        8=HI, 9=LS, 10=GE, 11=LT, 12=GT, 13=LE, 14=AL, 15=NV
static inline uint32_t arm64_bcc(int cond, int32_t insn_offset) {
    return 0x54000000u | (((uint32_t)insn_offset & 0x7FFFFu) << 5) | (uint32_t)(cond & 0xF);
}

// CBNZ Wn, #offset  (branch if Wn != 0, range ±1MB)
static inline uint32_t arm64_cbnz32(int rn, int32_t insn_offset) {
    return 0x35000000u | (((uint32_t)insn_offset & 0x7FFFFu) << 5) | (uint32_t)rn;
}

// CBZ Wn, #offset  (branch if Wn == 0)
static inline uint32_t arm64_cbz32(int rn, int32_t insn_offset) {
    return 0x34000000u | (((uint32_t)insn_offset & 0x7FFFFu) << 5) | (uint32_t)rn;
}

// -----------------------------------------------------------------------
// Misc
// -----------------------------------------------------------------------

// NOP
static inline uint32_t arm64_nop(void) {
    return 0xD503201Fu;
}

// MSR TPIDR_EL0, Xn  (write thread-local pointer — unused in iSH JIT but noted)
// ISB  (instruction sync barrier — not needed if sys_icache_invalidate is used)
```

### 4d. Block Translation Output Buffer

```c
// emu/jit_arm64.c — Translation state and helpers

#include "jit_arm64.h"
#include "jit.h"
#include "cpu.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Maximum instructions in one translation output buffer.
// JIT_BLOCK_MAX_BYTES / 4 = 8192 ARM64 instructions per block.
#define MAX_EMIT (JIT_BLOCK_MAX_BYTES / 4)

typedef struct {
    uint32_t buf[MAX_EMIT];  // ARM64 output buffer (scratch — copied into JIT region by jit_emit)
    int      count;           // Instructions emitted so far
    bool     overflow;        // Set if emit() was called past MAX_EMIT

    // Lazy EFLAGS state
    int       flags_op;       // Which operation set the flags (FLAGS_* enum)
    int       flags_lhs_reg;  // ARM64 register holding LHS operand
    int       flags_rhs_reg;  // ARM64 register holding RHS operand (or imm marker)
    uint32_t  flags_imm;      // Immediate value if flags_rhs_reg == -1

    // Tracking which x86 registers are "live" in ARM64 registers
    // vs. must be loaded from cpu_state on next read
    uint8_t   reg_live;       // Bitmask: bit i set = x86 reg i is live in ARM_REG_*

    // The guest EIP of the NEXT instruction after the translated block ends
    uint32_t  block_end_eip;
} trans_state_t;

static inline void emit(trans_state_t *s, uint32_t insn) {
    if (s->count < MAX_EMIT)
        s->buf[s->count++] = insn;
    else
        s->overflow = true;
}

// Emit a full 64-bit address load into register rd (uses 4 instructions worst case)
static void emit_load_addr64(trans_state_t *s, int rd, uint64_t addr) {
    emit(s, arm64_movz(rd, (uint16_t)(addr & 0xFFFF), 0));
    if (addr > 0xFFFF)
        emit(s, arm64_movk(rd, (uint16_t)((addr >> 16) & 0xFFFF), 16));
    if (addr > 0xFFFFFFFF)
        emit(s, arm64_movk(rd, (uint16_t)((addr >> 32) & 0xFFFF), 32));
    if (addr > 0xFFFFFFFFFFFF)
        emit(s, arm64_movk(rd, (uint16_t)((addr >> 48) & 0xFFFF), 48));
}

// Emit a call to a C helper function at absolute address `fn_ptr`.
// Uses TMP4 (x4) as the address register — caller must ensure x4 is scratch.
// ARM64 BL has ±128MB range. Helper functions in the iSH binary are likely
// farther than that from the JIT region, so we must use BLR.
static void emit_call_helper(trans_state_t *s, void (*fn_ptr)(void)) {
    emit_load_addr64(s, ARM_REG_TMP4, (uint64_t)(uintptr_t)fn_ptr);
    emit(s, arm64_blr(ARM_REG_TMP4));
}
```

### 4e. Block Prologue and Epilogue

Every translated block starts and ends with boilerplate ARM64 code:

```c
// Emit block prologue:
//   - Save callee-saved registers (x19-x27) to ARM stack
//   - Load cpu_state pointer from x0 (passed by jit_execute) into x19
//   - Load all x86 registers from cpu_state into dedicated ARM64 registers
static void emit_prologue(trans_state_t *s) {
    // STP pairs: save x19-x28 and x29/x30 onto the ARM stack
    // ARM64 ABI requires 16-byte stack alignment
    // STP x19, x20, [sp, #-96]!
    emit(s, 0xA9B413F3u);  // stp x19, x20, [sp, #-96]!
    emit(s, 0xA9011BF5u);  // stp x21, x22, [sp, #16]
    emit(s, 0xA90223F7u);  // stp x23, x24, [sp, #32]
    emit(s, 0xA9032BF9u);  // stp x25, x26, [sp, #48]
    emit(s, 0xA90433FBu);  // stp x27, x28, [sp, #64]
    emit(s, 0xA9057BFDu);  // stp x29, x30, [sp, #80]

    // x19 = cpu_state (passed in x0 by jit_execute caller convention)
    emit(s, arm64_mov_reg(ARM_REG_CPU, 0));

    // Load all x86 GPRs from cpu_state into dedicated ARM64 registers.
    // Uses the offsetof() values from struct cpu_state.
    // These must be LDR Wd (32-bit loads), zero-extending to 64 bits.
#define LOAD_REG(arm_r, field) \
    emit(s, arm64_ldr32(arm_r, ARM_REG_CPU, offsetof(struct cpu_state, field)))

    LOAD_REG(ARM_REG_EAX, eax);
    LOAD_REG(ARM_REG_ECX, ecx);
    LOAD_REG(ARM_REG_EDX, edx);
    LOAD_REG(ARM_REG_EBX, ebx);
    LOAD_REG(ARM_REG_ESP, esp);
    LOAD_REG(ARM_REG_EBP, ebp);
    LOAD_REG(ARM_REG_ESI, esi);
    LOAD_REG(ARM_REG_EDI, edi);
#undef LOAD_REG

    s->reg_live = 0xFF;  // All 8 GPRs are now live in ARM registers
}

// Emit block epilogue:
//   - Flush all live x86 registers back to cpu_state
//   - Store the updated EIP (block_end_eip) into cpu->eip
//   - Restore callee-saved ARM registers
//   - RET to jit_execute()
static void emit_epilogue(trans_state_t *s) {
    // Flush x86 GPRs back to cpu_state
#define STORE_REG(arm_r, field) \
    emit(s, arm64_str32(arm_r, ARM_REG_CPU, offsetof(struct cpu_state, field)))

    STORE_REG(ARM_REG_EAX, eax);
    STORE_REG(ARM_REG_ECX, ecx);
    STORE_REG(ARM_REG_EDX, edx);
    STORE_REG(ARM_REG_EBX, ebx);
    STORE_REG(ARM_REG_ESP, esp);
    STORE_REG(ARM_REG_EBP, ebp);
    STORE_REG(ARM_REG_ESI, esi);
    STORE_REG(ARM_REG_EDI, edi);
#undef STORE_REG

    // Store block_end_eip into cpu->eip using TMP0
    uint32_t tmp[2];
    int n = arm64_load_imm32(tmp, ARM_REG_TMP0, s->block_end_eip);
    for (int i = 0; i < n; i++) emit(s, tmp[i]);
    emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));

    // Restore callee-saved registers
    emit(s, 0xA9457BFDu);  // ldp x29, x30, [sp, #80]
    emit(s, 0xA94433FBu);  // ldp x27, x28, [sp, #64]
    emit(s, 0xA9432BF9u);  // ldp x25, x26, [sp, #48]
    emit(s, 0xA94223F7u);  // ldp x23, x24, [sp, #32]
    emit(s, 0xA9411BF5u);  // ldp x21, x22, [sp, #16]
    emit(s, 0xA8C613F3u);  // ldp x19, x20, [sp], #96
    emit(s, arm64_ret());
}
```

### 4f. Core Instruction Translations

```c
// emu/jit_arm64.c (continued) — x86 instruction translations

// ------------------------------------------------------------------
// MOV r32, r/m32  (opcode 0x8B: MOV Gd, Ed)
// MOV r/m32, r32  (opcode 0x89: MOV Ed, Gd)
// ------------------------------------------------------------------
static void translate_mov_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    // MOV Wd, Wn — 32-bit; ARM zero-extends result to 64 bits
    emit(s, arm64_mov_reg32(dst, src));
}

// MOV r32, imm32  (opcode group B8+rd)
static void translate_mov_r32_imm32(trans_state_t *s, int dst_x86, uint32_t imm) {
    int dst = x86_to_arm_reg[dst_x86];
    uint32_t tmp[2];
    int n = arm64_load_imm32(tmp, dst, imm);
    for (int i = 0; i < n; i++) emit(s, tmp[i]);
}

// ------------------------------------------------------------------
// ADD r/m32, r32  (opcode 0x01)
// ADD r32, r/m32  (opcode 0x03)
// ------------------------------------------------------------------
static void translate_add_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    // Save operands for lazy EFLAGS before the ADD
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, dst));  // TMP0 = old dst
    emit(s, arm64_mov_reg32(ARM_REG_TMP1, src));  // TMP1 = src
    // ADDS Wd, Wn, Wm — sets ARM NZCV flags (used by emit_compute_flags_add)
    emit(s, arm64_adds_reg32(dst, dst, src));
    // Store lazy flag info: we'll use ARM NZCV if flags are needed
    // In a full lazy implementation, store TMP0/TMP1 and FLAGS_ADD into
    // the trans_state. For simplicity here, we materialize NZCV directly.
    s->flags_op = FLAGS_ADD;
    s->flags_lhs_reg = ARM_REG_TMP0;
    s->flags_rhs_reg = ARM_REG_TMP1;
}

// ADD r32, imm32  (opcode 0x81 /0)
static void translate_add_r32_imm32(trans_state_t *s, int dst_x86, uint32_t imm) {
    int dst = x86_to_arm_reg[dst_x86];
    // Load imm into scratch
    uint32_t tmp[2];
    int n = arm64_load_imm32(tmp, ARM_REG_TMP1, imm);
    for (int i = 0; i < n; i++) emit(s, tmp[i]);
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, dst));  // Save LHS
    emit(s, arm64_adds_reg32(dst, dst, ARM_REG_TMP1));
    s->flags_op = FLAGS_ADD;
    s->flags_lhs_reg = ARM_REG_TMP0;
    s->flags_rhs_reg = ARM_REG_TMP1;
}

// ------------------------------------------------------------------
// SUB r/m32, r32  (0x29) / CMP r/m32, r32 (0x39)
// ------------------------------------------------------------------
static void translate_sub_r32_r32(trans_state_t *s, int dst_x86, int src_x86, bool discard_result) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, dst));
    emit(s, arm64_mov_reg32(ARM_REG_TMP1, src));
    // SUBS sets NZCV. For CMP, result is discarded (write to XZR).
    int rd = discard_result ? ARM_REG_XZR : dst;
    emit(s, arm64_subs_reg32(rd, dst, src));
    s->flags_op = FLAGS_SUB;
    s->flags_lhs_reg = ARM_REG_TMP0;
    s->flags_rhs_reg = ARM_REG_TMP1;
}

// ------------------------------------------------------------------
// AND/OR/XOR/TEST
// ------------------------------------------------------------------
static void translate_and_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    // ANDS sets NZCV.N and NZCV.Z; clears V and C (matching x86 AND behavior)
    emit(s, arm64_ands_reg32(dst, dst, src));
    s->flags_op = FLAGS_AND;
    s->flags_lhs_reg = dst;
    s->flags_rhs_reg = -1;  // Not needed for AND flag computation
}

static void translate_or_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    emit(s, arm64_orr_reg32(dst, dst, src));
    // ORR doesn't set NZCV. Must compute manually from result.
    // TST (ANDS with discard) the result against itself to set N/Z
    emit(s, arm64_ands_reg32(ARM_REG_XZR, dst, dst));
    s->flags_op = FLAGS_AND;
}

static void translate_xor_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    emit(s, arm64_eor_reg32(dst, dst, src));
    emit(s, arm64_ands_reg32(ARM_REG_XZR, dst, dst));
    s->flags_op = FLAGS_AND;
}

static void translate_test_r32_r32(trans_state_t *s, int dst_x86, int src_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    int src = x86_to_arm_reg[src_x86];
    // TEST: AND but discard result, just set flags
    emit(s, arm64_ands_reg32(ARM_REG_XZR, dst, src));
    s->flags_op = FLAGS_AND;
}

// ------------------------------------------------------------------
// INC / DEC
// ------------------------------------------------------------------
static void translate_inc_r32(trans_state_t *s, int dst_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, dst));
    emit(s, arm64_add_imm32(dst, dst, 1));
    // INC preserves CF — must not use ADDS (which would clobber CF).
    // Store result for lazy N/Z/O/A flag computation; CF is unchanged.
    s->flags_op = FLAGS_INC;
    s->flags_lhs_reg = ARM_REG_TMP0;
}

static void translate_dec_r32(trans_state_t *s, int dst_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, dst));
    emit(s, arm64_sub_imm32(dst, dst, 1));
    s->flags_op = FLAGS_DEC;
    s->flags_lhs_reg = ARM_REG_TMP0;
}

// ------------------------------------------------------------------
// NOT  (bitwise)
// ------------------------------------------------------------------
static void translate_not_r32(trans_state_t *s, int dst_x86) {
    int dst = x86_to_arm_reg[dst_x86];
    emit(s, arm64_mvn_reg32(dst, dst));
    // NOT does not modify EFLAGS
}

// ------------------------------------------------------------------
// XCHG r32, r32
// ------------------------------------------------------------------
static void translate_xchg_r32_r32(trans_state_t *s, int a_x86, int b_x86) {
    int ra = x86_to_arm_reg[a_x86];
    int rb = x86_to_arm_reg[b_x86];
    // Classic swap: TMP = ra; ra = rb; rb = TMP
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, ra));
    emit(s, arm64_mov_reg32(ra, rb));
    emit(s, arm64_mov_reg32(rb, ARM_REG_TMP0));
    // XCHG does not modify EFLAGS
}

// ------------------------------------------------------------------
// LEA r32, [base + index*scale + disp]
// ------------------------------------------------------------------
static void translate_lea_r32(trans_state_t *s, int dst_x86,
                               int base_x86, int index_x86, int scale, int32_t disp) {
    int dst   = x86_to_arm_reg[dst_x86];
    int base  = (base_x86  >= 0) ? x86_to_arm_reg[base_x86]  : ARM_REG_XZR;
    int index = (index_x86 >= 0) ? x86_to_arm_reg[index_x86] : ARM_REG_XZR;

    // TMP0 = index << log2(scale)
    if (index_x86 >= 0 && scale > 1) {
        // LSL Wd, Windex, #log2(scale)
        // LSL by immediate: UBFM Wd, Wn, #(-shift mod 32), #(31-shift)
        int shift = (scale == 2) ? 1 : (scale == 4) ? 2 : 3;
        // LSL Wd, Wn, #imm: encoded as UBFM Wd, Wn, #(32-imm), #(31-imm)
        emit(s, 0x53000000u | ((uint32_t)(32-shift) << 16) | ((uint32_t)(31-shift) << 10)
                            | ((uint32_t)index << 5) | (uint32_t)ARM_REG_TMP0);
        index = ARM_REG_TMP0;
    }

    // TMP1 = base + (scaled index)
    if (index_x86 >= 0) {
        emit(s, arm64_add_reg32(ARM_REG_TMP1, base, index));
    } else {
        emit(s, arm64_mov_reg32(ARM_REG_TMP1, base));
    }

    // TMP1 += disp
    if (disp != 0) {
        uint32_t tmp[2];
        int n = arm64_load_imm32(tmp, ARM_REG_TMP2, (uint32_t)disp);
        for (int i = 0; i < n; i++) emit(s, tmp[i]);
        emit(s, arm64_add_reg32(ARM_REG_TMP1, ARM_REG_TMP1, ARM_REG_TMP2));
    }

    emit(s, arm64_mov_reg32(dst, ARM_REG_TMP1));
    // LEA does not modify EFLAGS
}

// ------------------------------------------------------------------
// NOP  (opcode 0x90, or multi-byte NOP group 0F 1F)
// ------------------------------------------------------------------
static void translate_nop(trans_state_t *s) {
    emit(s, arm64_nop());
}
```

### 4g. Memory Access via iSH MMU

x86 guest memory accesses must go through iSH's MMU to translate 32-bit guest virtual addresses into host pointer dereferences. The TLB cache in `tlb.c` provides fast lookups. Do not directly dereference guest addresses — they are 32-bit values that live in a completely different address space from the 64-bit host.

```c
// Guest memory read helper — called from JIT code for load instructions.
// Arguments per ARM64 ABI: x0 = cpu_state*, x1 = guest 32-bit address
// Returns: x0 = value read (32-bit zero-extended)
// This function is a C helper called by the JIT via BLR.
uint32_t jit_helper_read32(struct cpu_state *cpu, uint32_t guest_addr) {
    // Attempt TLB lookup first (fast path)
    struct tlb_entry *entry = tlb_lookup(&cpu->tlb, guest_addr);
    if (__builtin_expect(entry != NULL, 1)) {
        // TLB hit: entry->host_ptr + offset gives us the host address
        uint32_t *host_ptr = (uint32_t *)((uint8_t *)entry->host_ptr
                                          + (guest_addr - entry->guest_page));
        return *host_ptr;
    }
    // TLB miss: full MMU walk
    return mmu_read32(cpu, guest_addr);
}

void jit_helper_write32(struct cpu_state *cpu, uint32_t guest_addr, uint32_t value) {
    struct tlb_entry *entry = tlb_lookup(&cpu->tlb, guest_addr);
    if (__builtin_expect(entry != NULL && entry->writable, 1)) {
        uint32_t *host_ptr = (uint32_t *)((uint8_t *)entry->host_ptr
                                          + (guest_addr - entry->guest_page));
        *host_ptr = value;
        // Check if we just wrote to a page that contains JIT-translated code.
        // If so, invalidate those blocks (self-modifying code support).
        if (__builtin_expect(entry->is_exec_page, 0)) {
            jit_cache_invalidate_range(guest_addr & ~0xFFF, (guest_addr & ~0xFFF) + 0x1000);
        }
        return;
    }
    mmu_write32(cpu, guest_addr, value);
}
```

**Emitting a PUSH instruction (uses guest memory write):**

```c
// PUSH r32  (opcode 50+rd)
static void translate_push_r32(trans_state_t *s, int src_x86) {
    int src = x86_to_arm_reg[src_x86];

    // ESP -= 4
    emit(s, arm64_sub_imm32(ARM_REG_ESP, ARM_REG_ESP, 4));

    // Call jit_helper_write32(cpu, esp, reg_value)
    // ARM64 ABI: x0=cpu, x1=guest_addr(esp), x2=value
    emit(s, arm64_mov_reg(0, ARM_REG_CPU));                    // x0 = cpu
    emit(s, arm64_mov_reg32(1, ARM_REG_ESP));                  // x1 = new esp
    emit(s, arm64_mov_reg32(2, src));                          // x2 = value to push
    emit_call_helper(s, (void(*)(void))jit_helper_write32);
    // After BLR, caller-saved registers (x0-x15) are clobbered.
    // Callee-saved x19-x27 (our GPR map) are preserved.
}

// POP r32  (opcode 58+rd)
static void translate_pop_r32(trans_state_t *s, int dst_x86) {
    int dst = x86_to_arm_reg[dst_x86];

    // Call jit_helper_read32(cpu, esp) → result in x0
    emit(s, arm64_mov_reg(0, ARM_REG_CPU));                    // x0 = cpu
    emit(s, arm64_mov_reg32(1, ARM_REG_ESP));                  // x1 = esp
    emit_call_helper(s, (void(*)(void))jit_helper_read32);
    // x0 = value read; move to destination register
    emit(s, arm64_mov_reg32(dst, 0));

    // ESP += 4
    emit(s, arm64_add_imm32(ARM_REG_ESP, ARM_REG_ESP, 4));
}
```

### 4h. Branch and Call Translation

```c
// JMP rel32  (opcode 0xE9) — unconditional direct branch
// Just update block_end_eip and end the block; jit_execute will dispatch to target.
static void translate_jmp_rel32(trans_state_t *s, uint32_t target_eip) {
    s->block_end_eip = target_eip;
    emit_epilogue(s);
}

// Jcc rel32 — conditional branch (16 cases: JE, JNE, JL, JGE, etc.)
// x86 condition codes require mapping from EFLAGS to ARM NZCV.
// This is only correct if the preceding instruction used ADDS/SUBS/ANDS
// (which set ARM NZCV in a way compatible with the expected flags).
// See Section 9 (Lazy EFLAGS) for the general case.
static void translate_jcc_rel32(trans_state_t *s,
                                 int x86_cc,          // 0-15 (x86 condition code)
                                 uint32_t taken_eip,   // EIP if branch taken
                                 uint32_t fallthrough_eip) {
    // Map x86 condition code to ARM64 condition code.
    // x86 cc: 0=O, 1=NO, 2=B/C, 3=AE/NC, 4=E/Z, 5=NE/NZ, 6=BE, 7=A,
    //         8=S, 9=NS, 10=P, 11=NP, 12=L, 13=GE, 14=LE, 15=G
    // ARM64 cc: 0=EQ, 1=NE, 2=CS, 3=CC, 4=MI, 5=PL, 6=VS, 7=VC,
    //           8=HI, 9=LS, 10=GE, 11=LT, 12=GT, 13=LE, 14=AL
    // Direct mapping for common cases (requires matching ADDS/SUBS above):
    static const int x86_to_arm_cc[16] = {
        6,   // 0: JO   → VS (overflow set)
        7,   // 1: JNO  → VC
        3,   // 2: JB   → CC (carry clear in ARM = below in unsigned)
             //          CORRECTION: ARM CC (cc=3) = carry clear = below = x86 JB ✓
        2,   // 3: JAE  → CS (carry set = above or equal)
             //          CORRECTION: ARM CS (cc=2) = carry set = x86 JAE ✓
        0,   // 4: JE   → EQ
        1,   // 5: JNE  → NE
        9,   // 6: JBE  → LS (lower or same)
        8,   // 7: JA   → HI (higher)
        4,   // 8: JS   → MI (minus/negative)
        5,   // 9: JNS  → PL (plus/positive)
        -1,  // 10: JP  — parity, ARM has no P flag; must compute in software
        -1,  // 11: JNP — same
        11,  // 12: JL  → LT
        10,  // 13: JGE → GE
        13,  // 14: JLE → LE
        12,  // 15: JG  → GT
    };

    int arm_cc = x86_to_arm_cc[x86_cc & 0xF];

    if (arm_cc == -1) {
        // Parity flag — fall back to interpreter for this branch
        emit_interpreter_fallback(s, s->block_end_eip);
        return;
    }

    // Emit: Bcc #taken_branch (if condition true, branch to taken path)
    // Bcc is PC-relative. Since we don't know the final address of these
    // instructions in the JIT region until jit_emit() runs, we emit a
    // placeholder and patch it. Alternatively: emit taken_eip store + epilogue,
    // then fallthrough_eip store + epilogue.
    //
    // Practical approach: emit two epilogues with different EIPs, selecting
    // via Bcc. This is simple and correct, if slightly larger.

    // Instruction sequence:
    //   Bcc #8  (skip over the "taken" epilogue load if condition NOT met → fallthrough)
    //   ... taken_eip store + ret ...
    //   ... fallthrough_eip store + ret ...

    // We need to know the taken epilogue size. Estimate: 2 (imm32 load) + 1 (str) + 6 (ldp pairs) + 1 (ret) = 10 insns
    // Emit a placeholder Bcc, then fill in the offset after counting taken epilogue size.
    int bcc_idx = s->count;
    emit(s, arm64_nop());  // Placeholder: will be patched below

    // Taken path: store taken_eip into cpu->eip, restore, ret
    {
        uint32_t tmp[2];
        int n = arm64_load_imm32(tmp, ARM_REG_TMP0, taken_eip);
        for (int i = 0; i < n; i++) emit(s, tmp[i]);
        emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));
    }
    // Emit register flush for taken path
    // (abbreviated — in practice emit_epilogue_body() without the bcc)
    emit_epilogue(s);  // This includes the RET — safe to call twice

    int taken_end = s->count;

    // Patch the placeholder: Bcc #(taken_end - bcc_idx) instructions forward
    // But we actually want: if condition TRUE → skip to fallthrough (not taken)
    // Correct logic: if condition FALSE → skip over taken epilogue
    // Bcc(INVERT(arm_cc), offset_to_fallthrough)
    // Invert condition: arm_cc ^ 1 (EQ↔NE, CS↔CC, MI↔PL, etc.)
    int inv_cc = arm_cc ^ 1;
    int offset_insns = taken_end - bcc_idx;  // Instructions from Bcc to fallthrough start
    s->buf[bcc_idx] = arm64_bcc(inv_cc, offset_insns);

    // Fallthrough path
    {
        uint32_t tmp[2];
        int n = arm64_load_imm32(tmp, ARM_REG_TMP0, fallthrough_eip);
        for (int i = 0; i < n; i++) emit(s, tmp[i]);
        emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));
    }
    emit_epilogue(s);
}

// CALL rel32  (opcode 0xE8)
// 1. Push return address onto guest stack.
// 2. End block with target_eip as block_end_eip.
// 3. jit_execute will look up target in JIT cache.
static void translate_call_rel32(trans_state_t *s, uint32_t target_eip, uint32_t return_addr) {
    // Push return_addr onto guest stack (ESP -= 4; mem[ESP] = return_addr)
    // Load return_addr into TMP0
    uint32_t tmp[2];
    int n = arm64_load_imm32(tmp, ARM_REG_TMP0, return_addr);
    for (int i = 0; i < n; i++) emit(s, tmp[i]);

    // ESP -= 4
    emit(s, arm64_sub_imm32(ARM_REG_ESP, ARM_REG_ESP, 4));

    // Write return_addr to guest [ESP]
    emit(s, arm64_mov_reg(0, ARM_REG_CPU));       // x0 = cpu
    emit(s, arm64_mov_reg32(1, ARM_REG_ESP));      // x1 = new esp
    emit(s, arm64_mov_reg32(2, ARM_REG_TMP0));     // x2 = return_addr
    emit_call_helper(s, (void(*)(void))jit_helper_write32);

    // Set block_end_eip to target and end the block
    s->block_end_eip = target_eip;
    emit_epilogue(s);
}

// RET  (opcode 0xC3)
// Pop return address from guest stack into EIP.
static void translate_ret(trans_state_t *s) {
    // Read [ESP] into TMP0 (the return address)
    emit(s, arm64_mov_reg(0, ARM_REG_CPU));
    emit(s, arm64_mov_reg32(1, ARM_REG_ESP));
    emit_call_helper(s, (void(*)(void))jit_helper_read32);
    // x0 = return address
    emit(s, arm64_mov_reg32(ARM_REG_TMP0, 0));

    // ESP += 4
    emit(s, arm64_add_imm32(ARM_REG_ESP, ARM_REG_ESP, 4));

    // Flush registers, then store x0 as the new EIP
    // (do NOT call emit_epilogue directly — it stores block_end_eip, not the dynamic addr)
    // Instead: flush GPRs, then STR TMP0 → cpu->eip, then restore ARM regs, RET
#define STORE_REG(arm_r, field) \
    emit(s, arm64_str32(arm_r, ARM_REG_CPU, offsetof(struct cpu_state, field)))
    STORE_REG(ARM_REG_EAX, eax);
    STORE_REG(ARM_REG_ECX, ecx);
    STORE_REG(ARM_REG_EDX, edx);
    STORE_REG(ARM_REG_EBX, ebx);
    STORE_REG(ARM_REG_ESP, esp);
    STORE_REG(ARM_REG_EBP, ebp);
    STORE_REG(ARM_REG_ESI, esi);
    STORE_REG(ARM_REG_EDI, edi);
#undef STORE_REG
    // cpu->eip = TMP0 (popped return address)
    emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));
    // Restore ARM callee-saved regs
    emit(s, 0xA9457BFDu);
    emit(s, 0xA94433FBu);
    emit(s, 0xA9432BF9u);
    emit(s, 0xA94223F7u);
    emit(s, 0xA9411BF5u);
    emit(s, 0xA8C613F3u);
    emit(s, arm64_ret());
}
```

### 4i. Interpreter Fallback for Untranslated Instructions

```c
// Fallback: flush all registers, call existing iSH interpreter for one instruction,
// reload all registers, and continue in JIT mode.
// This handles complex/rare instructions (string ops, FPU, segment overrides, RDTSC, etc.)
// without needing to implement them in the JIT.
static void emit_interpreter_fallback(trans_state_t *s, uint32_t current_eip) {
    // Flush all live registers to cpu_state (so the interpreter sees correct state)
#define STORE_REG(arm_r, field) \
    emit(s, arm64_str32(arm_r, ARM_REG_CPU, offsetof(struct cpu_state, field)))
    STORE_REG(ARM_REG_EAX, eax);
    STORE_REG(ARM_REG_ECX, ecx);
    STORE_REG(ARM_REG_EDX, edx);
    STORE_REG(ARM_REG_EBX, ebx);
    STORE_REG(ARM_REG_ESP, esp);
    STORE_REG(ARM_REG_EBP, ebp);
    STORE_REG(ARM_REG_ESI, esi);
    STORE_REG(ARM_REG_EDI, edi);
#undef STORE_REG

    // Store current EIP so interpreter knows where to resume
    uint32_t tmp[2];
    int n = arm64_load_imm32(tmp, ARM_REG_TMP0, current_eip);
    for (int i = 0; i < n; i++) emit(s, tmp[i]);
    emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));

    // Call the Asbestos single-instruction interpreter
    // extern void asbestos_interpret_one(struct cpu_state *cpu);
    extern void asbestos_interpret_one(struct cpu_state *);
    emit(s, arm64_mov_reg(0, ARM_REG_CPU));  // x0 = cpu
    emit_call_helper(s, (void(*)(void))asbestos_interpret_one);

    // Reload all registers (interpreter may have updated them)
#define LOAD_REG(arm_r, field) \
    emit(s, arm64_ldr32(arm_r, ARM_REG_CPU, offsetof(struct cpu_state, field)))
    LOAD_REG(ARM_REG_EAX, eax);
    LOAD_REG(ARM_REG_ECX, ecx);
    LOAD_REG(ARM_REG_EDX, edx);
    LOAD_REG(ARM_REG_EBX, ebx);
    LOAD_REG(ARM_REG_ESP, esp);
    LOAD_REG(ARM_REG_EBP, ebp);
    LOAD_REG(ARM_REG_ESI, esi);
    LOAD_REG(ARM_REG_EDI, edi);
#undef LOAD_REG

    // EIP was updated by interpreter — end the JIT block and let jit_execute
    // re-dispatch from the new EIP (which may be JIT-translated or not).
    // Do not emit a static epilogue; instead load the now-updated cpu->eip
    // and return (dynamic exit).
    emit(s, arm64_ldr32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));
    emit(s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU, offsetof(struct cpu_state, eip)));
    // Restore + RET (reuse epilogue sequence without overwriting EIP)
    emit(s, 0xA9457BFDu);
    emit(s, 0xA94433FBu);
    emit(s, 0xA9432BF9u);
    emit(s, 0xA94223F7u);
    emit(s, 0xA9411BF5u);
    emit(s, 0xA8C613F3u);
    emit(s, arm64_ret());
}
```

### 4j. Top-Level Translation Dispatch

```c
// jit_translate_block — entry point: decode x86, dispatch to translators
// Returns NULL on failure (e.g., memory access error during decode)
jit_block_t *jit_translate_block(struct cpu_state *cpu, uint32_t guest_eip) {
    trans_state_t s;
    memset(&s, 0, sizeof(s));
    s.flags_op = FLAGS_NONE;
    s.reg_live = 0;

    emit_prologue(&s);

    uint32_t eip = guest_eip;
    int insn_count = 0;
    bool block_ended = false;

    while (!block_ended && insn_count < 128 && !s.overflow) {
        // Fetch x86 instruction bytes from guest memory
        uint8_t opcode = jit_helper_fetch_byte(cpu, eip++);
        insn_count++;

        switch (opcode) {
        case 0x01: { // ADD r/m32, r32 (ModRM: /r)
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int dst = modrm & 7;  // r/m field (assume register-register, mod=11)
            int src = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) {
                translate_add_r32_r32(&s, dst, src);
            } else {
                // Memory destination — emit fallback
                emit_interpreter_fallback(&s, eip - 2);
                block_ended = true;
            }
            break;
        }
        case 0x03: { // ADD r32, r/m32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int dst = (modrm >> 3) & 7;
            int src = modrm & 7;
            if ((modrm >> 6) == 3) {
                translate_add_r32_r32(&s, dst, src);
            } else {
                emit_interpreter_fallback(&s, eip - 2);
                block_ended = true;
            }
            break;
        }
        case 0x29: { // SUB r/m32, r32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int dst = modrm & 7;
            int src = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) translate_sub_r32_r32(&s, dst, src, false);
            else { emit_interpreter_fallback(&s, eip - 2); block_ended = true; }
            break;
        }
        case 0x39: { // CMP r/m32, r32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int lhs = modrm & 7;
            int rhs = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) translate_sub_r32_r32(&s, lhs, rhs, true);
            else { emit_interpreter_fallback(&s, eip - 2); block_ended = true; }
            break;
        }
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47: // INC r32
            translate_inc_r32(&s, opcode & 7);
            break;
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: // DEC r32
            translate_dec_r32(&s, opcode & 7);
            break;
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: // PUSH r32
            translate_push_r32(&s, opcode & 7);
            break;
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: // POP r32
            translate_pop_r32(&s, opcode & 7);
            break;
        case 0x74: { // JE rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 4 /*JE*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x75: { // JNE rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 5 /*JNE*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x7C: { // JL rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 12 /*JL*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x7D: { // JGE rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 13 /*JGE*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x7E: { // JLE rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 14 /*JLE*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x7F: { // JG rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jcc_rel32(&s, 15 /*JG*/, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0x85: { // TEST r/m32, r32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int lhs = modrm & 7;
            int rhs = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) translate_test_r32_r32(&s, lhs, rhs);
            else { emit_interpreter_fallback(&s, eip - 2); block_ended = true; }
            break;
        }
        case 0x89: { // MOV r/m32, r32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int dst = modrm & 7;
            int src = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) translate_mov_r32_r32(&s, dst, src);
            else { emit_interpreter_fallback(&s, eip - 2); block_ended = true; }
            break;
        }
        case 0x8B: { // MOV r32, r/m32
            uint8_t modrm = jit_helper_fetch_byte(cpu, eip++);
            int dst = (modrm >> 3) & 7;
            int src = modrm & 7;
            if ((modrm >> 6) == 3) translate_mov_r32_r32(&s, dst, src);
            else { emit_interpreter_fallback(&s, eip - 2); block_ended = true; }
            break;
        }
        case 0x90: // NOP
            translate_nop(&s);
            break;
        case 0xC3: // RET (near)
            translate_ret(&s);
            block_ended = true;
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: { // MOV r32, imm32
            uint32_t imm = 0;
            for (int i = 0; i < 4; i++)
                imm |= (uint32_t)jit_helper_fetch_byte(cpu, eip++) << (i * 8);
            translate_mov_r32_imm32(&s, opcode & 7, imm);
            break;
        }
        case 0xE8: { // CALL rel32
            int32_t rel = 0;
            for (int i = 0; i < 4; i++)
                rel |= (int32_t)jit_helper_fetch_byte(cpu, eip++) << (i * 8);
            translate_call_rel32(&s, eip + rel, eip);
            block_ended = true;
            break;
        }
        case 0xE9: { // JMP rel32
            int32_t rel = 0;
            for (int i = 0; i < 4; i++)
                rel |= (int32_t)jit_helper_fetch_byte(cpu, eip++) << (i * 8);
            translate_jmp_rel32(&s, eip + rel);
            block_ended = true;
            break;
        }
        case 0xEB: { // JMP rel8
            int8_t rel = (int8_t)jit_helper_fetch_byte(cpu, eip++);
            translate_jmp_rel32(&s, eip + rel);
            block_ended = true;
            break;
        }
        default:
            // Unimplemented: fall back to interpreter for this instruction
            emit_interpreter_fallback(&s, eip - 1);
            block_ended = true;
            break;
        }
    }

    // If we exited the loop because insn_count hit 128 (too long block),
    // emit a normal epilogue with the current EIP as block_end.
    if (!block_ended) {
        s.block_end_eip = eip;
        emit_epilogue(&s);
    }

    if (s.overflow || s.count == 0)
        return NULL;

    // Write the ARM64 code into the JIT region
    void *host_ptr = jit_emit(s.buf, (size_t)s.count);
    if (!host_ptr)
        return NULL;

    // Fill in the block descriptor
    struct jit_block *block = pool_alloc();
    block->guest_eip     = guest_eip;
    block->host_ptr      = host_ptr;
    block->host_size     = (size_t)s.count * 4;
    block->guest_end_eip = eip;

    return block;
}
```

---

<a name="section-5"></a>
## Section 5: JIT Block Cache

The block cache is implemented in `jit.c` (see Section 3c). Key design decisions:

**Hash function:** Knuth multiplicative hashing (`eip * 2654435761u`) is fast (one multiply) and distributes x86 EIPs well because they cluster at call sites and loop headers. The `>> 16` shift keeps the high bits, which vary more for typical EIP distributions.

**Lockless lookup:** The hot path (cache hit) does not acquire a lock. ARM64's memory model guarantees that aligned 64-bit pointer stores are atomic. A lookup thread may observe a stale `NULL` (miss, harmless) or the newly inserted block pointer (correct). It cannot observe a torn pointer. Write ordering: the cache insert uses `__ATOMIC_RELEASE` to ensure the block data is visible before the pointer.

**Separate chaining:** Simple linked list per bucket. Worst-case O(n) per lookup if all EIPs hash to the same bucket, but with Knuth hashing and 65536 buckets this is very unlikely. Average case O(1).

**Invalidation:** Full flush (`memset(g_cache, 0)`) on JIT region wrap-around. Range invalidation (`jit_cache_invalidate_range`) for self-modifying code — O(n) but called rarely.

**Block pool:** Pre-allocated array of 65536 `jit_block_t` structs. Bump allocation with wrap-around. The pool and cache flush together on wrap. This eliminates `malloc()` from the hot path.

---

<a name="section-6"></a>
## Section 6: Integration with StikDebug — Startup Sequence

### 6a. Entitlement Verification

Before any code runs, verify the entitlement is present:

```bash
# After building and signing iSH:
codesign -d --entitlements - /path/to/iSH.app/iSH
# Must show: com.apple.security.cs.allow-jit = true
#            com.apple.security.cs.allow-jit-write-allowlist = true  
#            get-task-allow = true

# Also verify the provisioning profile covers these entitlements:
security cms -D -i /path/to/iSH.app/embedded.mobileprovision | grep -A2 "allow-jit"
```

### 6b. AppDelegate Integration

```objc
// app/AppDelegate.m

#import <UIKit/UIKit.h>
#include "jit.h"

extern bool g_use_jit;  // Global flag checked by iSH execution loop

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {

    // iSH needs the get-task-allow entitlement for StikDebug to attach.
    // StikDebug will call PT_ATTACHEXC on this process, setting CS_DEBUGGED.
    // We defer JIT init to give StikDebug time to attach.
    //
    // Why 2 seconds? StikDebug documentation says JIT activates within ~10 seconds,
    // but in practice the lockdown connection + debugserver attach completes in 1-3s
    // on LAN/loopback VPN. 2s is a conservative wait. A more robust implementation
    // would poll for CS_DEBUGGED using csops(2) rather than sleeping.

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
        ^{
            // Attempt JIT initialization. jit_init() will fail gracefully if
            // the debugger hasn't attached yet.
            int result = jit_init();
            if (result == 0) {
                NSLog(@"[iSH] JIT backend active — MAP_JIT succeeded on A17/TXM");
                NSLog(@"[iSH] JIT region: pthread_jit_write_with_callback_np available");
                g_use_jit = true;
            } else {
                NSLog(@"[iSH] JIT unavailable — using Asbestos interpreter");
                NSLog(@"[iSH] Tip: attach StikDebug before launching iSH for JIT support");
                g_use_jit = false;
            }

            // Start iSH Linux environment
            [self startISHShell];
        }
    );

    return YES;
}

// More robust alternative: poll for CS_DEBUGGED
static bool is_debugged(void) {
    // csops(2) with CS_OPS_STATUS returns the codesigning flags bitmask
    // CS_DEBUGGED = 0x10000000
    uint32_t flags = 0;
    int rc = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (rc != 0) return false;
    return (flags & 0x10000000) != 0;  // CS_DEBUGGED
}

- (void)pollForDebuggerAndInitJIT {
    // Spin for up to 30 seconds waiting for CS_DEBUGGED
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        for (int i = 0; i < 300; i++) {
            if (is_debugged()) {
                if (jit_init() == 0) {
                    NSLog(@"[iSH] JIT active (CS_DEBUGGED detected after %dms)", i * 100);
                    g_use_jit = true;
                }
                return;
            }
            usleep(100000);  // 100ms
        }
        NSLog(@"[iSH] StikDebug not attached after 30s — using interpreter");
        g_use_jit = false;
        [self startISHShell];
    });
}

@end
```

### 6c. Modifying the iSH Execution Loop

The iSH execution loop lives in the emulator dispatch. Add the JIT check:

```c
// In the main CPU execution loop (wherever Asbestos currently dispatches):

extern bool g_use_jit;

void cpu_run(struct cpu_state *cpu) {
    if (g_use_jit && jit_is_available()) {
        // JIT path
        jit_execute(cpu);
    } else {
        // Asbestos interpreter path (existing code, unchanged)
        asbestos_run(cpu);
    }
}
```

### 6d. User Steps for JIT-Enabled iSH on iPhone 15 Pro

1. Build iSH with a development certificate that includes all five entitlements from Section 3a. Use manual signing — Xcode automatic signing may strip non-standard entitlements.
2. Install via SideStore (requires separate SideStore setup with pairing file and LocalDevVPN).
3. Install StikDebug from the Official AltStore Source (or via SideStore).
4. Import the same pairing file into StikDebug (via iloader).
5. Open StikDebug. Ensure LocalDevVPN is active (green indicators in StikDebug).
6. **Open iSH first** — it will show a loading screen and wait ~2 seconds for the debugger.
7. **Immediately switch to StikDebug** → tap "Connect by App" → select iSH.
8. iSH receives `CS_DEBUGGED`, `jit_init()` succeeds, JIT execution begins.
9. If JIT fails (user sees "using Asbestos interpreter" in debug log), repeat from step 6.

**Note on iOS 26 compatibility:** SideStore docs confirm iOS 26 broke standard JIT for TXM devices. StikDebug released a fix update. Verify StikDebug version ≥ the fix release date (post-December 2025). Monitor the idevice Discord server's `#announcements` and `#compatibility` channels for updates.

---

<a name="section-7"></a>
## Section 7: x86 MMU Integration

The JIT must respect iSH's existing memory model. Key points:

### 7a. Address Space Layout

iSH's 32-bit x86 guest has a 4GB virtual address space. The iSH MMU maps ranges of this to host memory. The TLB in `tlb.c` caches recent mappings:

```
struct tlb_entry {
    uint32_t  guest_page;   // Guest VPN (page number, page-aligned)
    void     *host_ptr;     // Corresponding host VA for the page start
    bool      writable;     // Page is writable
    bool      is_exec_page; // Page may contain JIT-translated code
};
```

### 7b. Self-Modifying Code Detection

The iSH MMU must notify the JIT cache when a write occurs to a page that contains JIT-translated code. The `jit_helper_write32` function (Section 4g) handles this by calling `jit_cache_invalidate_range()`. The `is_exec_page` flag in the TLB entry enables this check with near-zero overhead on the non-SMC path (`__builtin_expect(..., 0)`).

### 7c. Page Fault Handling

When a guest memory access misses the TLB and the MMU's full walk returns a fault (unmapped page), iSH raises `INT_GPF`. The JIT's helper functions (`jit_helper_read32`, `jit_helper_write32`) call `mmu_read32`/`mmu_write32` which already implement this. No changes needed to the fault path.

---

<a name="section-8"></a>
## Section 8: System Call Handling in JIT Code

x86 Linux system calls are invoked via `int 0x80` (32-bit) or `syscall` (64-bit, not used in iSH's 32-bit emulation). In the JIT:

```c
// INT 0x80 handler — translate to iSH kernel dispatch
case 0xCD: { // INT n
    uint8_t n = jit_helper_fetch_byte(cpu, eip++);
    if (n == 0x80) {
        // Flush all registers (syscall may modify eax return value)
        // then call iSH's existing syscall handler, then reload
        emit_flush_all_regs(&s);
        // Store current EIP into cpu->eip
        uint32_t tmp[2];
        int nw = arm64_load_imm32(tmp, ARM_REG_TMP0, eip);
        for (int i = 0; i < nw; i++) emit(&s, tmp[i]);
        emit(&s, arm64_str32(ARM_REG_TMP0, ARM_REG_CPU,
                             offsetof(struct cpu_state, eip)));
        // call handle_interrupt(0x80, cpu)
        // handle_interrupt is in kernel/calls.c:490
        extern void handle_interrupt(int num, struct cpu_state *cpu);
        emit(&s, arm64_mov_reg(0, ARM_REG_CPU));  // x0 = cpu
        emit_load_imm_to(&s, 1, 0x80);            // x1 = 0x80
        emit_call_helper(&s, (void(*)(void))handle_interrupt);
        emit_reload_all_regs(&s);
    } else {
        // Other INT — interpreter fallback
        emit_interpreter_fallback(&s, eip - 2);
        block_ended = true;
    }
    break;
}
```

---

<a name="section-9"></a>
## Section 9: Lazy EFLAGS — Full Implementation

x86 EFLAGS (CF, PF, AF, ZF, SF, OF) are expensive to compute on every instruction. Most programs check flags only after specific instruction sequences (e.g., `CMP` + `JCC`). Lazy evaluation defers flag computation until actually needed.

```c
// emu/jit_eflags.c — Lazy EFLAGS for iSH JIT

#include "jit_arm64.h"
#include "cpu.h"

// EFLAGS operation types
typedef enum {
    FLAGS_NONE = 0,
    FLAGS_ADD,   // ADD/ADC: CF from carry, OF from signed overflow, ZF from zero, SF from sign, PF from parity
    FLAGS_SUB,   // SUB/SBB/CMP: same but inverted CF
    FLAGS_AND,   // AND/OR/XOR/TEST: CF=0, OF=0, ZF/SF/PF from result
    FLAGS_INC,   // INC: updates OF/SF/ZF/PF/AF, preserves CF
    FLAGS_DEC,   // DEC: same
    FLAGS_SHL,   // SHL/SHR: CF = last bit shifted out, OF = result sign change
    FLAGS_SAR,   // SAR: similar
} eflags_op_t;

// Lazy flags state stored in cpu_state alongside computed EFLAGS.
// The JIT stores the operands here instead of computing EFLAGS eagerly.
struct lazy_flags {
    eflags_op_t op;
    uint32_t    lhs;    // Left operand (before operation)
    uint32_t    rhs;    // Right operand
    uint32_t    result; // Result of operation
};

// Compute x86 EFLAGS from lazy_flags state.
// Called only when a flag-reading instruction is about to execute.
uint32_t compute_eflags(struct lazy_flags *lf) {
    uint32_t eflags = 0;
    uint32_t lhs = lf->lhs, rhs = lf->rhs, result = lf->result;

    switch (lf->op) {
    case FLAGS_NONE:
        return 0;  // No flags set

    case FLAGS_ADD:
        // CF: unsigned carry out of bit 31
        if ((uint64_t)lhs + rhs > 0xFFFFFFFF) eflags |= CF;
        // OF: signed overflow (both same sign, result different sign)
        if (!((lhs ^ rhs) & 0x80000000) && ((result ^ lhs) & 0x80000000))
            eflags |= OF;
        goto zf_sf_pf;

    case FLAGS_SUB:
        // CF: borrow (lhs < rhs for unsigned)
        if (lhs < rhs) eflags |= CF;
        // OF: signed overflow in subtraction
        if (((lhs ^ rhs) & 0x80000000) && ((result ^ lhs) & 0x80000000))
            eflags |= OF;
        goto zf_sf_pf;

    case FLAGS_AND:
        // CF = OF = 0 (already cleared by initial 0)
        goto zf_sf_pf;

    case FLAGS_INC:
        // CF preserved (not modified by INC). Only update OF/SF/ZF/PF.
        // OF: was 0x7FFFFFFF (max signed 32-bit), incremented to 0x80000000
        if (lhs == 0x7FFFFFFF) eflags |= OF;
        goto zf_sf_pf;

    case FLAGS_DEC:
        // OF: was 0x80000000, decremented to 0x7FFFFFFF
        if (lhs == 0x80000000) eflags |= OF;
        goto zf_sf_pf;

    zf_sf_pf:
        if (result == 0)          eflags |= ZF;
        if (result & 0x80000000)  eflags |= SF;
        // PF: parity of lowest byte (even number of 1 bits → PF=1)
        {
            uint8_t b = result & 0xFF;
            b ^= b >> 4; b ^= b >> 2; b ^= b >> 1;
            if (!(b & 1)) eflags |= PF;
        }
        break;

    default:
        break;
    }
    return eflags;
}

// x86 EFLAGS bit positions
#define CF  (1u <<  0)
#define PF  (1u <<  2)
#define AF  (1u <<  4)
#define ZF  (1u <<  6)
#define SF  (1u <<  7)
#define TF  (1u <<  8)
#define IF  (1u <<  9)
#define DF  (1u << 10)
#define OF  (1u << 11)
```

**JIT integration for lazy flags:** When the translator encounters an instruction that reads flags (Jcc, PUSHF, LAHF, SETCC, ADC, SBB, etc.), emit a call to a helper that:
1. Reads `cpu->lazy_flags`
2. Calls `compute_eflags()` → returns the full EFLAGS value
3. Stores individual flag bits into scratch registers for the reading instruction to use

The key insight: on a sequence like `CMP eax, ebx; JNE .target`, the `CMP` stores its operands into `lazy_flags`. The `JNE` triggers `compute_eflags()` once. No intermediate EFLAGS storage on every intervening instruction.

---

<a name="section-10"></a>
## Section 10: Implementation Roadmap

### Phase 1 — Infrastructure (1–2 weeks)

| Task | File | Notes |
|------|------|-------|
| Add entitlements | `iSH.entitlements` | All 5 keys; verify with `codesign -d` |
| Implement `jit_init()` | `emu/jit.c` | `mmap(MAP_JIT)`, fallback on failure |
| Implement `jit_emit()` | `emu/jit.c` | `pthread_jit_write_with_callback_np` + `sys_icache_invalidate` |
| Implement block cache | `emu/jit.c` | Hash table, pool allocator, lockless lookup |
| AppDelegate integration | `app/AppDelegate.m` | 2-second delay + `jit_init()` + fallback |
| Add to meson.build | `meson.build` | `emu/jit.c`, `emu/jit_arm64.c`, `emu/jit_eflags.c` |
| Test: MAP_JIT allocates | — | Verify with StikDebug attached |
| Test: Write callback works | — | Write known bytes, verify they execute |

### Phase 2 — Core Translator (2–4 weeks)

| Task | File | Notes |
|------|------|-------|
| ARM64 encoding helpers | `emu/jit_arm64.h` | All helpers in Section 4c |
| Block prologue/epilogue | `emu/jit_arm64.c` | Register save/restore, EIP update |
| Top-20 instruction translations | `emu/jit_arm64.c` | MOV, ADD, SUB, CMP, JMP, Jcc (all 14 non-parity), PUSH, POP, CALL, RET, AND, OR, XOR, NOT, TEST, LEA, NOP, INC, DEC, XCHG |
| Interpreter fallback emission | `emu/jit_arm64.c` | For unimplemented instructions |
| Lazy EFLAGS | `emu/jit_eflags.c` | Full `compute_eflags()` |
| Guest memory helpers | `emu/jit_arm64.c` | `jit_helper_read32/write32` via TLB |
| System call handler | `emu/jit_arm64.c` | INT 0x80 → `handle_interrupt` |
| Test: simple programs | — | `echo hello`, `ls`, `cat /etc/os-release` |

### Phase 3 — Coverage + Optimization (4–8 weeks)

| Task | Notes |
|------|-------|
| Remaining instructions | MUL, IMUL, DIV, IDIV, MOVSX, MOVZX, SHR, SHL, SAR, ROL, ROR, RCL, RCR, BSWAP, BSF, BSR, CMOV, string ops (REP MOVSD, REP STOSD) |
| ModRM memory addressing | SIB byte, displacement modes for load/store instructions |
| 8-bit and 16-bit operands | AL/AX sub-registers |
| Inline cache (IC) for indirect branches | Cache last target of CALL/JMP r/m32 directly in JIT code |
| Register allocation across blocks | Avoid prologue/epilogue if caller and callee share register state |
| Trace recording | Link consecutive blocks with direct ARM64 branches (no jit_execute overhead) |
| LRU eviction | Replace bump-pointer wrap with true LRU for JIT region |

### Estimated Performance on iPhone 15 Pro (A17)

| Workload | Asbestos (baseline) | Phase 2 JIT | Phase 3 JIT |
|----------|-------------------|-------------|-------------|
| Python CPU-bound (mandelbrot) | 1× | ~2–3× | ~4–6× |
| C compilation (gcc -O0) | 1× | ~3–4× | ~5–8× |
| Shell script loop | 1× | ~1.5–2× | ~2–3× |
| Integer arithmetic (dhrystone) | 1× | ~4–5× | ~8–12× |
| nmap port scan | 1× | ~2–3× | ~3–5× |

Figures are estimates based on iSH's published JIT prototype data (2–5× improvement on most tasks, per ish.app/blog/ish-jit-and-eu).

---

<a name="section-11"></a>
## Section 11: Key Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `mmap(MAP_JIT)` fails even with debugger attached | Medium | JIT unavailable | Graceful `g_use_jit = false` fallback; retry via polling for `CS_DEBUGGED` |
| `pthread_jit_write_with_callback_np` not available | Low (iOS 26.5 target) | Build failure | `#if __IPHONE_OS_VERSION_MIN_REQUIRED >= 170000` compile-time guard |
| Callback not in allow-list → crash | High (developer error) | Hard crash | `PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP` placed exactly once in main binary |
| JIT code produces wrong results | High (early phases) | Guest crashes/wrong output | Shadow mode: run JIT + interpreter in parallel, assert cpu_state equality |
| `sys_icache_invalidate` omitted | Critical | Non-deterministic crashes | Place `sys_icache_invalidate` call inside `jit_emit()` — impossible to forget |
| ARM NZCV flags ≠ x86 EFLAGS semantics | High | Incorrect Jcc branches | Use lazy EFLAGS `compute_eflags()` for all flag-reading instructions; test exhaustively |
| Self-modifying guest code | Medium | Stale JIT blocks executing wrong code | `is_exec_page` flag + `jit_cache_invalidate_range()` in write helper |
| StikDebug detaches mid-session | Medium | JIT region still mapped (OK), future MAP_JIT not needed (region already allocated) | Once `jit_init()` succeeds, the JIT region persists until `jit_destroy()` — detachment does not revoke it |
| Apple changes TXM behavior in future iOS | Low–Medium | JIT may break | Fallback to Asbestos always available; monitor idevice Discord |
| Pool overflow invalidates all blocks | Medium | Temporary performance regression | Implement LRU eviction in Phase 3; 65536 pool entries is large enough for Phase 1–2 |
| `PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP` in `.dylib` | Developer error | Callback not found → crash | The macro must be in the **main executable** `.c` file. iOS does not support `jit-write-allowlist-freeze-late` (macOS-only) |

---

<a name="section-12"></a>
## Section 12: Testing Strategy

### 12a. Unit Tests

```c
// tests/jit_test.c — Basic JIT sanity tests

// Test 1: MAP_JIT allocates
void test_jit_alloc(void) {
    assert(jit_init() == 0);
    assert(jit_is_available());
}

// Test 2: Emit and execute a trivial ARM64 function
// Function: ret (immediately returns)
void test_jit_emit_ret(void) {
    uint32_t insn = arm64_ret();
    void *code = jit_emit(&insn, 1);
    assert(code != NULL);
    typedef void (*fn_t)(void);
    ((fn_t)code)();  // Should return without crashing
}

// Test 3: Emit a function that adds two numbers
// ARM64: ADD W0, W0, W1; RET
void test_jit_add(void) {
    uint32_t insns[] = {
        arm64_add_reg32(0, 0, 1),  // W0 = W0 + W1
        arm64_ret()
    };
    typedef uint32_t (*fn_t)(uint32_t, uint32_t);
    fn_t fn = (fn_t)jit_emit(insns, 2);
    assert(fn != NULL);
    assert(fn(3, 4) == 7);
    assert(fn(0xFFFFFFFF, 1) == 0);  // 32-bit wrap
}

// Test 4: JIT block cache lookup/insert
void test_jit_cache(void) {
    struct jit_block b = { .guest_eip = 0x1000, .host_ptr = (void*)0xDEAD, .host_size = 4 };
    jit_cache_insert(&b);
    struct jit_block *found = jit_cache_lookup(0x1000);
    assert(found != NULL && found->host_ptr == (void*)0xDEAD);
    assert(jit_cache_lookup(0x2000) == NULL);
}
```

### 12b. Shadow Execution Mode

During development, run JIT and interpreter in lockstep:

```c
// Shadow mode: execute one instruction via JIT, then via interpreter.
// Compare cpu_state after each. Any divergence = JIT bug.
#ifdef JIT_SHADOW_MODE
void cpu_run_shadow(struct cpu_state *cpu) {
    struct cpu_state shadow = *cpu;
    
    // JIT step
    jit_execute_one_block(cpu);
    
    // Interpreter step (from same starting state)
    asbestos_interpret_one(&shadow);
    
    // Compare
    if (memcmp(&cpu->regs, &shadow.regs, sizeof(cpu->regs)) != 0) {
        fprintf(stderr, "JIT DIVERGENCE at EIP 0x%08X:\n", shadow.eip);
        // Print register diff
        abort();
    }
}
#endif
```

### 12c. Integration Tests

Run the following in iSH under JIT and compare output to native x86 Linux:

```bash
# Basic arithmetic
python3 -c "print(sum(range(1000000)))"  # Expected: 499999500000

# String operations (exercises MOVSD/STOSD fallbacks)
dd if=/dev/urandom bs=1M count=10 | sha256sum

# Compilation
echo '#include <stdio.h>\nint main(){printf("ok\\n");}' > t.c
gcc t.c -o t && ./t  # Expected: ok

# Branching-heavy code
find /usr -name "*.h" | wc -l
```

---

<a name="sources"></a>
## Sources

- [Apple JIT porting guide (Apple Developer Documentation)](https://developer.apple.com/documentation/apple_silicon/porting_just-in-time_compilers_to_apple_silicon) — defines `mmap(MAP_JIT)`, `pthread_jit_write_with_callback_np`, `PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP`, and all required entitlements
- [com.apple.security.cs.allow-jit entitlement (Apple Developer Documentation)](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit) — entitlement type, platform, and Hardened Runtime interaction
- [Modern iOS Security: A Deep Dive into SPTM, TXM, and Exclaves (arXiv 2510.09272)](https://arxiv.org/abs/2510.09272) — GL/EL privilege hierarchy, SPTM domain model, TXM code signing enforcement, GXF, SPRR, `GENTER` instruction, Frame Table Entries
- [SPTM/TXM/Exclaves overview (emergentmind.com)](https://www.emergentmind.com/papers/2510.09272) — summary of privilege level hierarchy and TXM role in code signing
- [Jailed Just-in-Time Compilation on iOS — Saagar Jha (2020)](https://saagarjha.com/blog/2020/02/23/jailed-just-in-time-compilation-on-ios/) — `ptrace(PT_TRACE_ME)` mechanism, `CS_DEBUGGED`, `get-task-allow` entitlement, dual-map W^X technique (superseded by TXM on A15+)
- [iSH architecture overview (Mintlify/Phineas1500)](https://mintlify.com/Phineas1500/ish/architecture/overview) — Asbestos interpreter design, `emu/` source layout, MMU/TLB architecture, `kernel/calls.c` syscall handler
- [iSH GitHub repository (ish-app/ish)](https://github.com/ish-app/ish) — top-level source tree structure, Asbestos README quote, 3–5× interpreter speedup figure
- [iSH, JIT, and the EU Digital Markets Act (ish.app)](https://ish.app/blog/ish-jit-and-eu) — current iSH performance (5–100× slower than native), JIT prototype results (2–5× improvement), Apple's denial of DMA interoperability request (September 2024), BrowserEngineKit comparison
- [macOS JIT Memory research — Outflank (2026)](https://www.outflank.nl/blog/2026/02/19/macos-jit-memory/) — `MAP_JIT` behavior on macOS Tahoe 26.2: multiple regions possible in practice, thread-specific write/exec permissions, `jit-write-allowlist` entitlement effect, equivalence of `allow-jit` and `allow-unsigned-executable-memory`
- [StikDebug GitHub (StephenDev0/StikDebug)](https://github.com/StephenDev0/StikDebug) — on-device JIT enabler for iOS 17.4+, powered by `idevice`, loopback VPN mechanism
- [SideStore JIT documentation](https://docs.sidestore.io/docs/advanced/jit) — iOS 26 JIT status, StikDebug prerequisites, TXM compatibility matrix, list of apps confirmed working on TXM (UTM, Amethyst, MeloNX, DolphiniOS)
- [LuaJIT iOS JIT discussion (GitHub issue #1072)](https://github.com/LuaJIT/LuaJIT/issues/1072) — confirms `allow-jit` cannot be used on App Store iOS; W^X via `mprotect` works under debugger without special entitlement on non-TXM devices
- [.NET Runtime: Apple JIT APIs investigation (GitHub issue #108423)](https://github.com/dotnet/runtime/issues/108423) — `pthread_jit_write_with_callback_np` integration notes, comparison with `pthread_jit_write_protect_np` (macOS-only), `BrowserEngineKit` alternative APIs
- [Apple OS Integrity documentation](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web) — Apple's official security model for iOS kernel integrity
