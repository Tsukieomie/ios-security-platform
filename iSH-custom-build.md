# iSH Custom Build: JIT, Entitlements, Patches & Signing

> **Audience:** Security researchers building a modified iSH to bypass architectural limitations and sideload it on iOS. Everything below assumes a non-jailbroken device unless explicitly noted.

---

## Table of Contents

1. [The Three Constraint Layers](#section-1-the-three-constraint-layers)
2. [JIT — The Full Picture](#section-2-jit--the-full-picture)
3. [Entitlements — Exact File](#section-3-entitlements--exact-file)
4. [AF_NETLINK and /proc Patches](#section-4-af_netlink-and-proc-patches)
5. [Complete Build Instructions](#section-5-complete-build-instructions)
6. [What Each Approach Actually Fixes](#section-6-what-each-approach-actually-fixes)
7. [Existing Automated Builds](#section-7-existing-automated-builds)
8. [CoreTrust / AMFI Chain](#section-8-coretrust--amfi-chain-how-signing-actually-works)
9. [Recommended Approach by iOS Version](#section-9-recommended-approach-by-ios-version)

---

## Section 1: The Three Constraint Layers

iSH faces three distinct layers of constraints. They differ sharply in their origin, enforcement mechanism, and bypass-ability. Conflating them is the most common mistake in custom-build attempts.

### Layer A: Apple Policy Constraints (Enforced by Signing)

These are rules Apple encodes in its signing infrastructure, not in the kernel itself. The kernel enforces them only indirectly, by refusing to execute code that AMFI deems improperly signed.

| Constraint | Enforcement Point | Notes |
|---|---|---|
| No JIT / `MAP_JIT` without entitlement | AMFI + CoreTrust | Apple grants `com.apple.security.cs.allow-jit` to browsers only |
| No `dynamic-codesigning` entitlement | AMFI + PPL on A12+ | Allows W+X memory; PPL-protected on A12+ even with TrollStore |
| App Store won't allow unsigned-code execution | App Review + signing chain | Only affects App Store distribution path |
| No sideloaded unsigned binaries | Gatekeeper equivalent on iOS | All code must be Apple-signed or signed with dev cert |

**Bypass-ability: Partial.** Sideloading via TrollStore, AltStore, SideStore, or Sideloadly bypasses App Store policy constraints. Entitlement tricks (`get-task-allow` + `ptrace`) bypass some JIT restrictions. PPL-protected entitlements on A12+ cannot be bypassed without a jailbreak.

### Layer B: iOS Kernel Constraints (Enforced by XNU)

These are architectural gaps: XNU simply does not implement certain Linux kernel interfaces. iSH must emulate them entirely in userspace — there is no mechanism to "unlock" them.

| Constraint | Why It Exists | Emulation Possible? |
|---|---|---|
| No `AF_NETLINK` socket family | XNU doesn't expose `PF_NETLINK` to userland | Yes — implement fake netlink socket in `kernel/sock.c` |
| No raw sockets (`SOCK_RAW`) | Restricted at XNU kernel level for sandboxed apps | Partial — raw socket emulation over UDP is limited |
| No `/proc` filesystem | XNU has no procfs; iSH synthesizes `/proc` entirely | Yes — extend `fs/proc/` |
| No `/proc/net/dev`, `/proc/net/arp` | Not yet emulated in iSH | Yes — implement using `getifaddrs()` and `sysctl()` |
| No `SOCK_PACKET` / packet capture | XNU doesn't expose this without special entitlement | No — requires jailbreak or BPF entitlement |

**Bypass-ability: Software only.** Every missing interface must be implemented inside iSH's emulation layer. No entitlement or signing trick helps here.

### Layer C: Fundamental Architecture Constraints (No Bypass Without Jailbreak)

These constraints are enforced by the Secure Enclave and the Page Protection Layer (PPL). They are physically enforced in hardware / firmware and cannot be bypassed from EL0.

| Constraint | Enforcement | Bypass Without Jailbreak? |
|---|---|---|
| Cannot execute unsigned ARM64 code | PPL (A12+) + AMFI | No |
| Cannot run native arm64 Alpine binaries | Code signing — they aren't Apple-signed | No |
| Cannot access kernel memory or bypass sandbox | XNU sandbox + SEP | No |
| Cannot write to `/usr` or system partitions | APFS seal + sandbox | No |
| Cannot load kernel extensions | KPP / KTRR + PPL | No |

**Bypass-ability: None without a jailbreak that includes a PPL bypass** (e.g., palera1n checkm8-based, or a hypothetical future PPL exploit for A12+). iSH will always run as a 32-bit x86 interpreter — it cannot execute native Alpine arm64 binaries without jailbreak, regardless of any entitlement tricks.

---

## Section 2: JIT — The Full Picture

### 2a. Why JIT Matters for iSH

iSH's interpreter (codenamed "Asbestos") uses a direct-threaded code technique — faster than naive switch dispatch, but still interpreted. Performance benchmarks at **5–100x slower than native**, depending on workload.

From iSH's [EU DMA Article 6(7) interoperability request](https://ish.app/blog/ish-jit-and-eu) (filed July 2024, denied September 2024):

- Prototypes demonstrated **2–5x speedup on almost all tasks** from simple code generation alone
- Up to **10x speedup on compute-heavy workloads**
- iSH used Apple's BrowserEngineKit as a reference implementation for isolated JIT subprocesses
- Apple's denial response (verbatim): *"After review, we have determined that it does not fall in scope of article 6(7) DMA. Apple does not itself offer emulation functionalities on iOS and it does not offer JIT compilation for non-browser apps on iOS."*

**iSH is not dead.** The project releases automated weekly builds via GitHub Actions. As of April 2026, the most recent verified builds are:

| Build | Date |
|---|---|
| 773 | 12 Apr 2025 |
| 772 | 29 Mar 2025 |
| 771 | 22 Mar 2025 |
| 770 | 15 Mar 2025 |
| 768 | 01 Mar 2025 |
| 767 | 22 Feb 2025 |

(See [https://github.com/ish-app/ish/releases](https://github.com/ish-app/ish/releases) for the live list.)

### 2b. The Three JIT Approaches (In Detail)

#### Approach 1: MAP_JIT with `com.apple.security.cs.allow-jit` Entitlement

This entitlement allows `mmap()` with `MAP_JIT`, creating memory that is simultaneously writable and executable (true RWX). Safari, JavaScriptCore, and WebKit use this.

```xml
<key>com.apple.security.cs.allow-jit</key>
<true/>
```

The full `mmap()` call:
```c
void *jit_mem = mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_JIT | MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
);
// jit_mem is now simultaneously writable and executable
// Write ARM64 code here, then execute it directly
```

**iOS availability matrix:**

| Platform | Availability | Notes |
|---|---|---|
| macOS (Hardened Runtime) | Yes | Granted freely to any app |
| iOS App Store | No | Apple does not grant to non-browser apps |
| iOS TrollStore, pre-A12 (A11 and older) | Yes | `dynamic-codesigning` not PPL-protected on pre-A12 |
| iOS TrollStore, A12+ | No | PPL blocks `dynamic-codesigning`; app crashes on launch |
| iOS AltStore / SideStore / Sideloadly | No | Entitlement present but ignored without Apple grant |

Adding `com.apple.security.cs.allow-jit` to the entitlements file has **no effect** on standard sideloading — Apple's signing infrastructure on iOS will not honor it without a backend capability grant. It only works on TrollStore on pre-A12 devices (A11, A10X, A10, A9X, A9, A8X, A8, A7) running iOS 14.0–16.6.1 or 17.0.

The underlying entitlement that actually enables the memory model is `dynamic-codesigning`, which is PPL-protected on A12+:

```
com.apple.private.security.dynamic-codesigning  ← banned on A12+ by TrollStore even
```

#### Approach 2: W^X JIT via `ptrace(PT_TRACE_ME)` — The "Jailed JIT" Technique

Discovered and documented by [Saagar Jha](https://saagarjha.com/blog/2020/02/23/jailed-just-in-time-compilation-on-ios/) (February 2020). This is the technique used by Delta, PPSSPP, DolphiniOS, and other sideloaded emulators.

**Mechanism:**

1. App calls `ptrace(PT_TRACE_ME, 0, NULL, 0)` on itself at startup
2. XNU sets the `CS_DEBUGGED` flag on the process's code signing status
3. `CS_DEBUGGED` disables `CS_KILL` and `CS_HARD` enforcement
4. The process can now use `mprotect()` to flip pages between `PROT_WRITE` and `PROT_EXEC` (Write XOR Execute — never simultaneously W+X from any single virtual address)
5. True simultaneous RWX (needed for a real JIT buffer) requires double-mapping: map the same physical page at two virtual addresses — one with `PROT_WRITE`, one with `PROT_EXEC`

The double-map technique for effective RWX:
```c
// On iOS with CS_DEBUGGED set (after PT_TRACE_ME):
// Step 1: Create anonymous shared memory
int fd = shm_open("/jit_region", O_RDWR | O_CREAT, 0600);
ftruncate(fd, size);

// Step 2: Map once writable
uint8_t *write_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);

// Step 3: Map same physical pages executable at different VA
uint8_t *exec_ptr = mmap(NULL, size, PROT_READ | PROT_EXEC,
                         MAP_SHARED, fd, 0);

// Now: write_ptr[n] and exec_ptr[n] are the same physical byte
// Write ARM64 code via write_ptr, execute via exec_ptr
memcpy(write_ptr, arm64_code, code_size);
__builtin___clear_cache(exec_ptr, exec_ptr + code_size); // ARM cache flush
typedef void (*fn_t)(void);
((fn_t)exec_ptr)(); // Execute JIT code
```

`ptrace` is not in the public iOS SDK but is present in every process. Access it via `dlsym`:

```objc
// In AppDelegate.m — call before UIApplicationMain or any iSH initialization
#include <dlfcn.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <pthread.h>

// PT_TRACE_ME and PT_SIGEXC values (not in iOS SDK headers)
#define PT_TRACE_ME 0
#define PT_SIGEXC   12

typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);

// Mach exception handler to prevent system hangs when CS_DEBUGGED is set.
// Without this, any signal that would normally kill the app hangs the system
// because launchd doesn't know it's being "traced".
boolean_t exc_server(mach_msg_header_t *, mach_msg_header_t *);

kern_return_t catch_exception_raise(mach_port_t exception_port,
                                    mach_port_t thread,
                                    mach_port_t task,
                                    exception_type_t exception,
                                    exception_data_t code,
                                    mach_msg_type_number_t code_count) {
    // Forward to the system crash reporter (ReportCrash)
    return KERN_FAILURE;
}

static void *exception_handler_thread(void *arg) {
    mach_port_t port = *(mach_port_t *)arg;
    mach_msg_server(exc_server, 2048, port, 0);
    return NULL;
}

static void enable_jit(void) {
    // Load ptrace via dlsym — not in iOS SDK but present in libsystem_kernel
    ptrace_ptr_t ptrace_f = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (!ptrace_f) return;

    // PT_TRACE_ME: mark this process as being traced
    // Sets CS_DEBUGGED flag, disabling CS_KILL / CS_HARD enforcement
    ptrace_f(PT_TRACE_ME, 0, NULL, 0);

    // PT_SIGEXC: convert BSD signals to Mach EXC_SOFTWARE exceptions
    // Critical: without this, unhandled signals hang the whole system
    ptrace_f(PT_SIGEXC, 0, NULL, 0);

    // Install Mach exception port so signals don't hang the system
    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    task_set_exception_ports(mach_task_self(),
                             EXC_MASK_SOFTWARE,
                             port,
                             EXCEPTION_DEFAULT,
                             THREAD_STATE_NONE);
    pthread_t t;
    pthread_create(&t, NULL, exception_handler_thread, (void *)&port);
    pthread_detach(t);
}
```

Insert into `application:didFinishLaunchingWithOptions:` **before any iSH initialization**:

```objc
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    enable_jit(); // Must be first
    // ... rest of iSH initialization
    return YES;
}

// Prevent launchd confusion on app termination
- (void)applicationWillTerminate:(UIApplication *)application {
    exit(0);
}
```

Required entitlement (enables `ptrace` attachment):
```xml
<key>get-task-allow</key>
<true/>
```

**Limitations:**
- `get-task-allow` is a development-only entitlement — automatically stripped from App Store and TestFlight submissions by Apple's signing pipeline
- The W^X constraint means JIT code must be written through one VA and executed through another (double-map pattern above)
- After `execve(2)`, the traced state is inherited — handle carefully if iSH ever `exec`s subprocesses
- `PT_SIGEXC` conflicts with external debugger attachment via `PT_ATTACHEXC` — you can't use both simultaneously
- `SIGKILL` cannot be converted to a Mach exception — hard kills still immediately terminate the process

#### Approach 3: StikDebug / SideJITServer (External Debugger Attachment)

Rather than embedding `ptrace(PT_TRACE_ME)` in iSH itself, an external app attaches to iSH via the Mach debug port, causing XNU to set `CS_DEBUGGED` on the target process.

**StikDebug** ([GitHub: StephenDev0/StikDebug](https://github.com/StephenDev0/StikDebug)):
- Sideloaded app that acts as an on-device debugger/JIT activator
- Uses the `idevice` library (implemented via LocalDevVPN for network tunneling to the lockdown daemon)
- Works on iOS 17.4+ through iOS 26 (current)
- On iOS 26, support is limited to specific apps due to TXM (Trusted Execution Monitor) changes — older non-TXM-capable hardware retains full support
- Requires re-attachment after every app relaunch (JIT is lost on force-close)

**SideJITServer** ([GitHub: nythepegasus/SideJITServer](https://github.com/nythepegasus/SideJITServer)):
- Python tool running on a connected Mac/PC
- Uses `pymobiledevice3` to attach the debugger remotely over USB/WiFi
- Covers iOS 17.0–18.3 (confirmed); tested broken on iOS 18.4 as of April 2025
- Requires USB or LAN connection each time

**What iSH needs for either approach to work:**
```xml
<!-- iSH must be signed with get-task-allow for any external debugger to attach -->
<key>get-task-allow</key>
<true/>
```

Without `get-task-allow`, the lockdown daemon / AMFI will reject debugger attachment. No code changes to iSH's runtime logic are needed — the JIT speedup comes purely from `CS_DEBUGGED` relaxing code signing enforcement, which allows the existing interpreter to use `mprotect()` freely.

**TrollStore JIT shortcut** (TrollStore 2.0.12+):
```
apple-magnifier://enable-jit?bundle-id=<iSH_bundle_id>
```
This triggers TrollStore's built-in JIT enablement, which performs the debugger attach on your behalf.

#### Comparison Table

| Approach | iOS Version | Perf Gain | Code Change Needed | Signing | Persistence |
|---|---|---|---|---|---|
| `MAP_JIT` / `dynamic-codesigning` | Pre-A12, iOS ≤16.6.1 / 17.0, TrollStore | ~10x (true RWX) | Add entitlement + `MAP_JIT` mmap calls | TrollStore ldid | Permanent |
| W^X JIT (`PT_TRACE_ME` in code) | Any sideloadable iOS | ~3–5x | Add `enable_jit()` at startup + `get-task-allow` | Any dev cert | Per-launch (startup call self-re-enables) |
| StikDebug external attach | iOS 17.4–26 (non-TXM) | ~3–5x | Add `get-task-allow` entitlement only | Any dev cert | Per-launch (re-attach needed) |
| SideJITServer external attach | iOS 17.0–18.3 | ~3–5x | Add `get-task-allow` entitlement only | Any dev cert | Per-launch (re-attach needed) |
| No JIT (current App Store build) | All | 1x baseline | None | App Store | Permanent |

### 2c. What iSH's Interpreter Actually Needs to Use JIT

iSH's "Asbestos" interpreter uses **direct-threaded code**: x86 instructions are compiled into sequences of function pointers called *gadgets*, stored in `fiber_block` structs. Each gadget is a small ARM64 assembly function that executes one operation and tail-calls the next gadget via `gret`. This is faster than switch dispatch (~3–5x) but still fundamentally interpreted.

The core data structures (from [`asbestos/`](https://github.com/ish-app/ish/tree/master/emu/asbestos)):

```c
// Each translated x86 basic block becomes a fiber_block
struct fiber_block {
    addr_t addr;         // x86 guest address this block starts at
    addr_t end_addr;     // x86 guest address this block ends at
    size_t used;         // Number of gadget words used
    unsigned long *jump_ip[2];    // Patchable jump targets for block chaining
    unsigned long old_jump_ip[2];
    struct list jumps_from[2];
    struct list chain;            // Hash table linkage
    struct list page[2];          // Page tracking for invalidation
    struct list jetsam;           // Free list
    bool is_jetsam;
    unsigned long code[];         // Gadget array (variable length, flexible array)
};

// The Asbestos JIT manager
struct asbestos {
    struct mmu *mmu;
    size_t mem_used;
    size_t num_blocks;
    struct list *hash;       // Hash table: x86 address → fiber_block
    size_t hash_size;
    struct list jetsam;      // Blocks pending free
    struct { struct list blocks[2]; } *page_hash;  // Page → blocks tracking
    lock_t lock;
    wrlock_t jetsam_lock;
};
```

Register mapping (from [`asbestos/gadgets-aarch64/entry.S`](https://github.com/ish-app/ish/blob/master/emu/asbestos/gadgets-aarch64/entry.S)):

```asm
// ARM64 host registers permanently allocated to interpreter state:
// _ip   (x19): pointer into current fiber_block.code[] — the gadget stream
// _cpu  (x20): pointer to cpu_state struct (x86 register file)
// _tlb  (x21): pointer to TLB entries array

// x86 general-purpose registers are loaded into ARM64 registers for the
// duration of a fiber_block execution, then flushed back via store_regs.
```

**To upgrade Asbestos to emit actual ARM64 machine code (a real JIT backend):**

The current gadget array (`unsigned long code[]`) holds function pointers and inline immediates. A JIT backend would replace this with emitted ARM64 instructions. The key infrastructure changes:

```c
// 1. Allocate a writable JIT code buffer (after CS_DEBUGGED is set)
static uint8_t *jit_write_ptr;
static uint8_t *jit_exec_ptr;
static size_t   jit_capacity;

void jit_init(size_t capacity) {
    // Double-map for effective RWX under W^X constraint
    int fd = shm_open("/ish_jit", O_RDWR | O_CREAT | O_TRUNC, 0600);
    shm_unlink("/ish_jit");  // Unlink name, keep fd open
    ftruncate(fd, capacity);
    jit_write_ptr = mmap(NULL, capacity, PROT_READ|PROT_WRITE,
                         MAP_SHARED, fd, 0);
    jit_exec_ptr  = mmap(NULL, capacity, PROT_READ|PROT_EXEC,
                         MAP_SHARED, fd, 0);
    jit_capacity  = capacity;
    close(fd);
}

// 2. Emit ARM64 instruction into JIT buffer (write side)
static size_t jit_offset = 0;

static inline void emit32(uint32_t insn) {
    assert(jit_offset + 4 <= jit_capacity);
    memcpy(jit_write_ptr + jit_offset, &insn, 4);
    jit_offset += 4;
}

// ARM64 instruction encoding helpers
#define A64_MOV_REG(rd, rn)      (0xAA0003E0 | ((rn)<<16) | (rd))
#define A64_ADD_IMM(rd, rn, imm) (0x91000000 | ((imm)<<10) | ((rn)<<5) | (rd))
#define A64_LDR_IMM(rt, rn, imm) (0xB9400000 | (((imm)/4)<<10) | ((rn)<<5) | (rt))
#define A64_STR_IMM(rt, rn, imm) (0xB9000000 | (((imm)/4)<<10) | ((rn)<<5) | (rt))
#define A64_RET()                (0xD65F03C0)
#define A64_NOP()                (0xD503201F)

// 3. Flush ARM I-cache after writing code
static inline void jit_flush(void *exec_start, size_t len) {
    __builtin___clear_cache(exec_start, (char*)exec_start + len);
}
```

The JIT translation layer must handle:

| Problem | x86 Concept | ARM64 Target | Complexity |
|---|---|---|---|
| Register mapping | EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP | w0–w7 or dedicated ARM64 regs | Low |
| Flag computation | EFLAGS (CF, ZF, SF, OF, PF, AF) | NZCV + software flags | High — partial flags are expensive |
| Memory access | Segmented + virtual | Physical via iSH MMU/TLB | High — every load/store needs TLB lookup |
| Syscall trapping | `int 0x80` / `syscall` opcode | Call into iSH Linux syscall handler | Medium |
| Self-modifying code | Guest writes to own code | Invalidate fiber_blocks for that page | Medium |
| Unaligned access | x86 allows it freely | ARM64 requires alignment or EL0 config | Low (iOS allows unaligned EL0 access) |

**Estimated implementation effort:** A minimal JIT covering the common integer instruction set (no FPU/SSE initially) is approximately 3,000–5,000 lines of C for the code generator, plus significant testing. The PT_TRACE_ME approach (Section 2b) delivers 3–5x speedup with fewer than 50 lines of new code.

---

## Section 3: Entitlements — Exact File

### Current iSH App Store Entitlements

The production App Store build uses a minimal entitlements set. The file is at [`iSH.entitlements`](https://github.com/ish-app/ish) in the repo root:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Required for Files.app integration and app group container sharing -->
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.app.ish.iSH</string>
    </array>

    <!-- File Provider extension for iOS Files.app integration -->
    <key>com.apple.developer.fileprovider.testing-mode</key>
    <true/>
</dict>
</plist>
```

### Enhanced Entitlements for Custom Sideloaded Build

This file targets **AltStore / SideStore / Sideloadly** (any iOS version). Sections for TrollStore-only extras are commented out with explanations.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

    <!-- ═══════════════════════════════════════════════════════
         STANDARD — Keep for Files.app integration
         Update the group ID to match your bundle ID
         ═══════════════════════════════════════════════════════ -->
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.yourname.ish-enhanced</string>
    </array>

    <!-- ═══════════════════════════════════════════════════════
         JIT — REQUIRED for W^X JIT and all external JIT tools
         (StikDebug, SideJITServer, TrollStore JIT enabler)
         
         DEVELOPMENT ONLY: stripped from App Store submissions.
         Works with: AltStore, SideStore, Sideloadly, TrollStore.
         ═══════════════════════════════════════════════════════ -->
    <key>get-task-allow</key>
    <true/>

    <!-- ═══════════════════════════════════════════════════════
         MEMORY — Increases memory limit from ~1.5 GB to ~3 GB
         
         Apple grants this to some App Store apps (Xcode, etc.).
         Works with any signing method; Apple respects it via AMFI.
         Useful for large Alpine package installs, compilers.
         ═══════════════════════════════════════════════════════ -->
    <key>com.apple.developer.kernel.increased-memory-limit</key>
    <true/>

    <!-- ═══════════════════════════════════════════════════════
         MEMORY — Extended virtual address space
         
         Expands the app's VA space from ~4 GB to ~12 GB on 64-bit.
         Helps for emulating workloads with large memory maps.
         ═══════════════════════════════════════════════════════ -->
    <key>com.apple.developer.kernel.extended-virtual-addressing</key>
    <true/>

    <!-- ═══════════════════════════════════════════════════════
         NETWORK — Standard network client/server capability
         
         Required for outbound connections from within iSH.
         Already present in most sideloaded builds implicitly.
         ═══════════════════════════════════════════════════════ -->
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>


    <!-- ═══════════════════════════════════════════════════════
         TROLLSTORE ONLY — Unsandboxing
         
         DANGER: These break AltStore/SideStore signing.
         Only enable for TrollStore installs.
         
         com.apple.private.security.no-sandbox:
           Removes the sandbox entirely. iSH can write anywhere
           in its container and access other apps' data.
           Use with extreme caution.
         ═══════════════════════════════════════════════════════ -->
    <!--
    <key>com.apple.private.security.no-sandbox</key>
    <true/>
    <key>com.apple.private.security.storage.AppDataContainers</key>
    <true/>
    -->


    <!-- ═══════════════════════════════════════════════════════
         TROLLSTORE + PRE-A12 ONLY — True RWX JIT
         
         dynamic-codesigning: Allows simultaneous W+X memory.
         This IS the entitlement that makes MAP_JIT work at the
         kernel level.
         
         STATUS ON A12+: PPL-PROTECTED — causes crash on launch
         even with TrollStore. Cannot be used on A12+ devices
         regardless of iOS version or signing method.
         
         STATUS ON PRE-A12 (A11, A10X, A10, A9X, A9, A8X, A8, A7):
         Works with TrollStore on iOS 14.0–16.6.1 and 17.0.
         ═══════════════════════════════════════════════════════ -->
    <!--
    <key>dynamic-codesigning</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    -->


    <!-- ═══════════════════════════════════════════════════════
         NEVER USE — PPL-BANNED on A12+ (iOS 15+)
         
         These three entitlements are specifically blacklisted
         by TrollStore's documentation for A12+ / iOS 15+.
         Apps signed with them crash immediately on launch.
         They are PPL-protected — only a full PPL bypass
         (jailbreak) can grant them.
         
         com.apple.private.cs.debugger
         com.apple.private.skip-library-validation
         ═══════════════════════════════════════════════════════ -->

</dict>
</plist>
```

### TrollStore Entitlement Rules (Critical Reference)

Source: [opa334/TrollStore README](https://github.com/opa334/TrollStore)

**Supported iOS versions:**
- 14.0 beta 2 – 16.6.1
- 16.7 RC (build 20H18 specifically)
- 17.0 (exactly — not 17.0.1)
- **Never supported:** 16.7.x (excluding 16.7 RC), 17.0.1+, any iOS 18, any iOS 26

**The three PPL-banned entitlements (A12+, iOS 15+):**

| Entitlement | Effect If Used | Status on A12+ |
|---|---|---|
| `com.apple.private.cs.debugger` | External debugger capabilities | Crash on launch |
| `dynamic-codesigning` | Simultaneous W+X memory | Crash on launch |
| `com.apple.private.skip-library-validation` | Skip dylib signature checks | Crash on launch |

TrollStore signs binaries using `ldid` with fake entitlements:
```bash
ldid -S<entitlements.plist> <binary>
```

TrollStore's CoreTrust bypass exploits incorrect handling of binaries with multiple CMS signers, allowing a non-Apple certificate with App Store-equivalent capability. This is a **permanent** install — no 7-day cert rotation.

---

## Section 4: AF_NETLINK and /proc Patches

These are purely software fixes inside iSH's emulation layer. No entitlements are needed, and they work on any iOS version.

### 4a. AF_NETLINK — What It Would Take

AF_NETLINK is the Linux kernel's primary IPC mechanism for kernel–userspace communication about network topology. XNU provides none of this; iSH must synthesize it entirely.

**Tools that need AF_NETLINK:**

| Tool | Netlink Usage | Error Without It |
|---|---|---|
| `ip link` | `RTM_GETLINK` — list interfaces | `socket(AF_NETLINK,3,0): Invalid argument` |
| `ip addr` | `RTM_GETADDR` — list addresses | Same |
| `ip route` | `RTM_GETROUTE` — routing table | Same |
| `ifconfig` | `SIOCGIFCONF` ioctl + `AF_NETLINK` | `/proc/net/dev: No such file or directory` |
| `ss` | Netlink stats queries | Fails silently or errors |
| `nmap` | `AF_NETLINK` for host discovery | `route_dst_netlink: cannot create AF_NETLINK socket` |

**iOS data sources to back the emulation:**

| Linux Netlink Data | iOS Equivalent |
|---|---|
| Interface list, addresses | `getifaddrs()` → `struct ifaddrs` |
| Interface statistics (bytes/packets) | `sysctl(CTL_NET, PF_LINK, IFMIB_IFDATA, ...)` |
| Routing table | `sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0)` |
| ARP table | `sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_LLINFO)` |

**Implementation approach** — in `kernel/sock.c`, intercept `socket(AF_NETLINK, ...)` syscall:

```c
// iSH translates Linux socket() syscall in kernel/sock.c
// AF_NETLINK = 16 in Linux (note: different from XNU's PF_ROUTE = 17)
#define LINUX_AF_NETLINK 16
#define LINUX_NETLINK_ROUTE 0

// Fake netlink socket backed by a Unix socket pair
struct fake_netlink {
    int fd_read;    // iSH reads from here
    int fd_write;   // iSH writes requests to here
    int protocol;   // NETLINK_ROUTE, NETLINK_AUDIT, etc.
    uint32_t pid;   // Fake kernel PID = 0
    uint32_t seq;   // Sequence number tracker
};

// In sock_socket() handler:
case LINUX_AF_NETLINK:
    return fake_netlink_socket_create(type, protocol);
```

The netlink message format for `RTM_GETLINK` response (must be synthesized from `getifaddrs()`):

```c
// Linux netlink message structures (must be defined — not available in iOS SDK)
struct nlmsghdr {
    uint32_t nlmsg_len;    // Total length including header
    uint16_t nlmsg_type;   // RTM_NEWLINK, RTM_NEWADDR, etc.
    uint16_t nlmsg_flags;  // NLM_F_MULTI, NLM_F_DONE, etc.
    uint32_t nlmsg_seq;    // Sequence number
    uint32_t nlmsg_pid;    // Sender PID (kernel = 0)
};

struct ifinfomsg {
    uint8_t  ifi_family;   // AF_UNSPEC
    uint8_t  __ifi_pad;
    uint16_t ifi_type;     // ARPHRD_ETHER, ARPHRD_LOOPBACK, etc.
    int32_t  ifi_index;    // Interface index
    uint32_t ifi_flags;    // IFF_UP | IFF_RUNNING | ...
    uint32_t ifi_change;   // 0xFFFFFFFF for request
};

// Fake RTM_GETLINK response generation:
static int build_rtm_newlink_response(struct ifaddrs *ifa,
                                       char *buf, size_t buflen) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi = (struct ifinfomsg *)(nlh + 1);

    // Get interface index from iOS
    int ifindex = if_nametoindex(ifa->ifa_name);

    // Determine interface type
    uint16_t type = ARPHRD_ETHER;
    if (strcmp(ifa->ifa_name, "lo0") == 0) type = ARPHRD_LOOPBACK;

    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type   = type;
    ifi->ifi_index  = ifindex;
    ifi->ifi_flags  = ifa->ifa_flags; // IFF_UP, IFF_RUNNING, etc.
    ifi->ifi_change = 0xFFFFFFFF;

    // Append IFLA_IFNAME attribute
    // Append IFLA_MTU attribute
    // Append IFLA_ADDRESS (MAC address) from struct sockaddr_dl
    // ... RTA_* attribute encoding
    
    size_t total_len = NLMSG_ALIGN(sizeof(*nlh) + sizeof(*ifi) + attrs_len);
    nlh->nlmsg_len  = total_len;
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_MULTI;
    return total_len;
}
```

Key netlink message types to implement (priority order):

| Message Type | Linux Constant | Used By | iOS Data Source |
|---|---|---|---|
| `RTM_GETLINK` | 18 | `ip link`, `ifconfig`, `nmap` | `getifaddrs()` + `if_nametoindex()` |
| `RTM_GETADDR` | 22 | `ip addr`, `ifconfig` | `getifaddrs()` AF_INET / AF_INET6 |
| `RTM_GETROUTE` | 26 | `ip route`, `route` | `sysctl(CTL_NET, PF_ROUTE, ...)` |
| `NLMSG_DONE` | 3 | All multipart responses | Synthetic |
| `NLMSG_ERROR` | 2 | Error responses | Synthetic |

Estimated implementation: ~600–900 lines of C. Would fix `ip link`, `ip addr`, `ip route`, `ifconfig`, `ss`, and nmap host discovery in one pass.

### 4b. /proc/net Entries — What's Missing and How to Add Them

**Currently implemented in iSH** (partial, from [`fs/proc/net.c`](https://github.com/ish-app/ish/tree/master/fs/proc)):

```
/proc/net/tcp       — TCP socket table (partial)
/proc/net/tcp6      — TCP6 socket table (partial)
/proc/net/unix      — Unix domain socket table (partial)
```

**Missing entries and their iOS data sources:**

| /proc/net Entry | What Uses It | iOS Data Source | Complexity |
|---|---|---|---|
| `/proc/net/dev` | `ifconfig`, `netstat -i`, many tools | `getifaddrs()` + IFMIB sysctl | Low |
| `/proc/net/route` | `route`, `ip route` (fallback) | `sysctl(CTL_NET, PF_ROUTE, NET_RT_DUMP)` | Medium |
| `/proc/net/arp` | `arp -n`, neighbor discovery | `sysctl(CTL_NET, PF_ROUTE, NET_RT_FLAGS, RTF_LLINFO)` | Medium |
| `/proc/net/if_inet6` | DHCPv6 clients, IPv6 tools | `getifaddrs()` AF_INET6 entries | Low |
| `/proc/net/fib_trie` | Advanced routing tools | Complex; rarely needed | High |
| `/proc/net/sockstat` | `ss`, socket statistics | Count from existing socket table | Low |

**Implementation for `/proc/net/dev`:**

```c
// In fs/proc/net.c
// Expected format (Linux kernel):
// Inter-|   Receive                                                |  Transmit
//  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed

static ssize_t proc_net_dev_read(struct file *file, char *buf,
                                  size_t count, off_t *offset) {
    struct ifaddrs *ifaddr = NULL, *ifa;
    char *output = NULL;
    size_t output_len = 0;
    FILE *mem = open_memstream(&output, &output_len);

    // Write header lines
    fprintf(mem,
        "Inter-|   Receive                                                "
        "|  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast"
        "|bytes    packets errs drop fifo colls carrier compressed\n");

    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            // Only process AF_LINK entries (link layer = one entry per interface)
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK)
                continue;

            // Get interface statistics via SIOCGIFDATA ioctl or IFMIB sysctl
            struct if_data ifdata = {0};
            int mib[] = {CTL_NET, PF_LINK, IFMIB_IFDATA,
                         if_nametoindex(ifa->ifa_name), IFDATA_GENERAL};
            size_t sz = sizeof(struct ifmibdata);
            struct ifmibdata mibdata;
            sysctl(mib, 5, &mibdata, &sz, NULL, 0);
            ifdata = mibdata.ifmd_data;

            fprintf(mem,
                "%6s: %7llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu "
                "%7llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
                ifa->ifa_name,
                (unsigned long long)ifdata.ifi_ibytes,
                (unsigned long long)ifdata.ifi_ipackets,
                (unsigned long long)ifdata.ifi_ierrors,
                (unsigned long long)ifdata.ifi_iqdrops,
                0ULL, 0ULL, 0ULL,  // fifo, frame, compressed
                (unsigned long long)ifdata.ifi_imcasts, // multicast
                (unsigned long long)ifdata.ifi_obytes,
                (unsigned long long)ifdata.ifi_opackets,
                (unsigned long long)ifdata.ifi_oerrors,
                0ULL, 0ULL, 0ULL,  // drop, fifo, colls
                (unsigned long long)ifdata.ifi_collisions,
                0ULL               // compressed
            );
        }
        freeifaddrs(ifaddr);
    }

    fclose(mem);
    // Copy output to buf respecting count and offset...
    // (standard proc read pattern)
    ssize_t result = proc_simple_read(buf, output, output_len, count, offset);
    free(output);
    return result;
}
```

**Implementation for `/proc/net/route`** (routing table via XNU sysctl):

```c
#include <net/route.h>
#include <net/if_dl.h>

static ssize_t proc_net_route_read(struct file *file, char *buf,
                                    size_t count, off_t *offset) {
    // Linux /proc/net/route format:
    // Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
    // All values in hex, network byte order

    // Fetch routing table from XNU
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t needed = 0;
    sysctl(mib, 6, NULL, &needed, NULL, 0);
    char *rtbuf = malloc(needed);
    sysctl(mib, 6, rtbuf, &needed, NULL, 0);

    char *output = NULL;
    size_t output_len = 0;
    FILE *mem = open_memstream(&output, &output_len);

    fprintf(mem, "Iface\tDestination\tGateway\tFlags\tRefCnt\t"
                 "Use\tMetric\tMask\tMTU\tWindow\tIRTT\n");

    // Parse struct rt_msghdr entries
    char *end = rtbuf + needed;
    for (char *p = rtbuf; p < end; ) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)p;
        if (rtm->rtm_version != RTM_VERSION) { p += rtm->rtm_msglen; continue; }
        if (rtm->rtm_type != RTM_GET && rtm->rtm_type != RTM_ADD) {
            p += rtm->rtm_msglen; continue;
        }

        // Parse sockaddrs following the rt_msghdr
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct in_addr dest = {0}, gw = {0}, mask = {0};
        char ifname[IFNAMSIZ] = "unknown";

        // RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_IFP extraction
        // ... (iterate through rtm->rtm_addrs bitmask)

        char dest_hex[9], gw_hex[9], mask_hex[9];
        snprintf(dest_hex, 9, "%08X", dest.s_addr);
        snprintf(gw_hex,   9, "%08X", gw.s_addr);
        snprintf(mask_hex, 9, "%08X", mask.s_addr);

        fprintf(mem, "%s\t%s\t%s\t%04X\t0\t0\t%d\t%s\t0\t0\t0\n",
                ifname, dest_hex, gw_hex,
                (unsigned int)rtm->rtm_flags,
                (int)rtm->rtm_rmx.rmx_hopcount,
                mask_hex);

        p += rtm->rtm_msglen;
    }

    free(rtbuf);
    fclose(mem);
    ssize_t result = proc_simple_read(buf, output, output_len, count, offset);
    free(output);
    return result;
}
```

**Registering new /proc/net entries** (in iSH's procfs registration code):

```c
// In fs/proc/net.c, add to the proc_net_files table:
static struct proc_dir_entry proc_net_entries[] = {
    // Existing:
    { "tcp",    proc_net_tcp_read    },
    { "tcp6",   proc_net_tcp6_read   },
    { "unix",   proc_net_unix_read   },
    // New additions:
    { "dev",    proc_net_dev_read    },  // ifconfig, netstat -i
    { "route",  proc_net_route_read  },  // ip route fallback
    { "arp",    proc_net_arp_read    },  // arp -n
    { "if_inet6", proc_net_if_inet6_read }, // IPv6 tooling
    { NULL, NULL }
};
```

---

## Section 5: Complete Build Instructions

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| macOS | Any recent | Required for Xcode |
| Xcode | 15.0+ | Available free from App Store |
| Apple Developer Account | Free or paid | Free works for 7-day sideloading |
| Git | Any | For cloning with submodules |
| `ldid` (optional) | Latest | For manual re-signing; `brew install ldid` |

### Step 1: Clone iSH with Submodules

```bash
git clone --recurse-submodules https://github.com/ish-app/ish.git
cd ish

# Verify submodules are populated
ls emu/asbestos/  # Should show gadget assembly files
```

If you cloned without `--recurse-submodules`:
```bash
git submodule update --init --recursive
```

### Step 2: Configure Bundle ID and Signing

Locate `iSH.xcconfig` in the repo root. Edit:

```bash
# iSH.xcconfig
ROOT_BUNDLE_IDENTIFIER = com.yourname.ish-enhanced
DEVELOPMENT_TEAM = XXXXXXXXXX   # Your 10-char Team ID
```

Find your Team ID:
```bash
# Option 1: Xcode → Settings → Accounts → select account → team ID shown
# Option 2: security find-certificate -a -p | openssl x509 -noout -subject
# Option 3: xcrun altool --list-providers -u you@example.com -p @keychain:AC_PASSWORD
```

### Step 3: Apply Entitlement Patches

Replace the entitlements file:

```bash
cat > iSH.entitlements << 'ENTITLEMENTS_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.yourname.ish-enhanced</string>
    </array>
    <key>get-task-allow</key>
    <true/>
    <key>com.apple.developer.kernel.increased-memory-limit</key>
    <true/>
    <key>com.apple.developer.kernel.extended-virtual-addressing</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
</dict>
</plist>
ENTITLEMENTS_EOF
```

Verify the Xcode project references this file:
```bash
grep -r "iSH.entitlements" *.xcodeproj/
# Should show the entitlements file is referenced in CODE_SIGN_ENTITLEMENTS
```

### Step 4: Apply PT_TRACE_ME JIT Patch (Recommended)

Locate `app/AppDelegate.m`. Find `application:didFinishLaunchingWithOptions:`. Add the JIT enablement code **before any other initialization**:

```bash
# First, find the actual method signature in the file
grep -n "didFinishLaunchingWithOptions" app/AppDelegate.m
```

The patch (add to top of `AppDelegate.m` imports and the function body):

```objc
// At the top of AppDelegate.m, add these includes:
#include <dlfcn.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <pthread.h>

// PT_TRACE_ME and PT_SIGEXC — not in iOS public headers
#define ISH_PT_TRACE_ME 0
#define ISH_PT_SIGEXC   12

typedef int (*ish_ptrace_t)(int, pid_t, caddr_t, int);

boolean_t exc_server(mach_msg_header_t *, mach_msg_header_t *);

kern_return_t catch_exception_raise(mach_port_t ep, mach_port_t thread,
    mach_port_t task, exception_type_t exc,
    exception_data_t code, mach_msg_type_number_t code_count) {
    return KERN_FAILURE; // Forward to crash reporter
}

static void *ish_exception_thread(void *arg) {
    mach_port_t port = *(mach_port_t *)arg;
    mach_msg_server(exc_server, 2048, port, 0);
    return NULL;
}

static void ish_enable_jit(void) {
    ish_ptrace_t pt = (ish_ptrace_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (!pt) {
        NSLog(@"[iSH-JIT] ptrace not found via dlsym — JIT not enabled");
        return;
    }

    int result = pt(ISH_PT_TRACE_ME, 0, NULL, 0);
    if (result != 0) {
        NSLog(@"[iSH-JIT] PT_TRACE_ME failed: %d (errno %d)", result, errno);
        return;
    }
    NSLog(@"[iSH-JIT] PT_TRACE_ME succeeded — CS_DEBUGGED set");

    // Convert signals to Mach exceptions (prevents system hangs on crash)
    pt(ISH_PT_SIGEXC, 0, NULL, 0);

    // Install software exception handler for EXC_SOFTWARE
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                           MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) return;
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    task_set_exception_ports(mach_task_self(), EXC_MASK_SOFTWARE, port,
                             EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    pthread_t t;
    pthread_create(&t, NULL, ish_exception_thread, (void *)&port);
    pthread_detach(t);
}
```

In `application:didFinishLaunchingWithOptions:`:
```objc
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    ish_enable_jit();  // ← Add this line FIRST
    
    // ... existing iSH initialization code below ...
    return YES;
}

// Add this to prevent system hang on app termination while CS_DEBUGGED
- (void)applicationWillTerminate:(UIApplication *)application {
    exit(0);
}
```

### Step 5: Build

**Via Xcode GUI:**
1. Open `iSH.xcodeproj`
2. Select the `iSH` target
3. Product → Destination → select your connected device
4. Product → Build (⌘B) or Product → Run (⌘R) to build and install directly

**Via command line (connected device):**
```bash
# List available devices
xcrun xctrace list devices

# Build and install directly to device
xcodebuild \
  -scheme iSH \
  -destination 'platform=iOS,name=YourDeviceName' \
  -configuration Release \
  DEVELOPMENT_TEAM=YOUR_TEAM_ID \
  CODE_SIGN_IDENTITY="Apple Development" \
  build

# If build fails with provisioning errors, resolve in Xcode first:
# Xcode → iSH target → Signing & Capabilities → fix provisioning profile
```

**Check that `get-task-allow` survived the build:**
```bash
# After build, find the binary in DerivedData:
BINARY=$(find ~/Library/Developer/Xcode/DerivedData -name iSH -type f \
         -path "*/Release-iphoneos/*" 2>/dev/null | head -1)

# Dump embedded entitlements from Mach-O
codesign -d --entitlements :- "$BINARY" 2>/dev/null | \
  plutil -p -   # Should show get-task-allow = 1
```

### Step 6: Export IPA

For distribution via TrollStore, SideStore, or Sideloadly (rather than direct Xcode install):

```bash
# Archive first
xcodebuild \
  -scheme iSH \
  -destination 'generic/platform=iOS' \
  -configuration Release \
  DEVELOPMENT_TEAM=YOUR_TEAM_ID \
  archive \
  -archivePath build/iSH.xcarchive
```

Create `ExportOptions.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>development</string>
    <key>teamID</key>
    <string>YOUR_TEAM_ID</string>
    <key>compileBitcode</key>
    <false/>
    <key>stripSwiftSymbols</key>
    <false/>
    <key>thinning</key>
    <string>&lt;none&gt;</string>
</dict>
</plist>
```

```bash
xcodebuild -exportArchive \
  -archivePath build/iSH.xcarchive \
  -exportPath build/output/ \
  -exportOptionsPlist ExportOptions.plist

# IPA will be at build/output/iSH.ipa
ls -la build/output/iSH.ipa
```

### Step 7: Re-sign a Downloaded IPA (Skip Build from Source)

To add entitlements to an existing IPA downloaded from GitHub Releases:

```bash
# 1. Download the IPA
curl -L -o iSH.ipa \
  "https://github.com/ish-app/ish/releases/download/builds/773/iSH.ipa"
# (Adjust tag to the actual release tag — check the releases page for exact URLs)

# 2. Unpack
mkdir -p iSH_payload
unzip -q iSH.ipa -d iSH_payload

# 3. Locate the binary
BINARY="iSH_payload/Payload/iSH.app/iSH"
file "$BINARY"  # Should show: Mach-O 64-bit executable arm64

# 4. Inspect current entitlements
codesign -d --entitlements :- "$BINARY" 2>/dev/null

# 5. Write your enhanced entitlements (as above)
cat > enhanced.entitlements << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.application-groups</key>
    <array><string>group.com.yourname.ish-enhanced</string></array>
    <key>get-task-allow</key>
    <true/>
    <key>com.apple.developer.kernel.increased-memory-limit</key>
    <true/>
    <key>com.apple.developer.kernel.extended-virtual-addressing</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
</dict>
</plist>
EOF

# 6. Re-sign with ldid (TrollStore path) or codesign (dev cert path)

# Option A: ldid (for TrollStore — fakesign)
ldid -S enhanced.entitlements "$BINARY"

# Option B: codesign (for AltStore/Sideloadly — needs identity)
IDENTITY=$(security find-identity -v -p codesigning | \
           grep "Apple Development" | head -1 | \
           awk '{print $2}')
codesign --force --sign "$IDENTITY" \
         --entitlements enhanced.entitlements \
         "$BINARY"

# 7. Repack as IPA
cd iSH_payload
zip -r ../iSH-enhanced.ipa Payload/
cd ..

# 8. Verify entitlements survived repacking
unzip -p iSH-enhanced.ipa Payload/iSH.app/iSH | \
  codesign -d --entitlements :- /dev/stdin 2>/dev/null || true

# (Use proper codesign check on the binary itself, not piped)
codesign -d --entitlements :- iSH_payload/Payload/iSH.app/iSH 2>/dev/null
```

### Step 8: Install

**TrollStore (iOS 14.0–16.6.1 / 16.7 RC / 17.0):**
```bash
# Transfer iSH-enhanced.ipa to device (AirDrop, Files.app, etc.)
# Open with TrollStore → Install
# Or use the URL scheme (from Safari on device):
# apple-magnifier://install?url=https://your-server.com/iSH-enhanced.ipa

# TrollStore will re-sign with its CoreTrust bypass automatically
# JIT enablement after install:
# apple-magnifier://enable-jit?bundle-id=com.yourname.ish-enhanced
```

**SideStore / AltStore (any iOS):**
```bash
# Add the IPA to SideStore/AltStore via the + button
# Or use the AltStore source JSON if you want to self-host
# After install, enable JIT via StikDebug each launch
```

**Sideloadly (any iOS, requires connected Mac/PC):**
```bash
# 1. Open Sideloadly
# 2. Drag iSH-enhanced.ipa into the window
# 3. Enter Apple ID credentials
# 4. Click Start
# 5. After install, toggle JIT in Sideloadly's Advanced section
#    OR use StikDebug on-device
```

**StikJIT / SideJITServer (JIT enablement post-install):**
```bash
# SideJITServer — run on connected Mac
pip3 install SideJITServer pymobiledevice3
SideJITServer --pair     # Trust device when prompted
SideJITServer            # Start server
# On device: run Shortcut → SideJIT → select iSH → launch

# StikDebug — on-device only (iOS 17.4+)
# 1. Ensure LocalDevVPN is running
# 2. Open StikDebug → Connect by App → select iSH
# 3. iSH launches with CS_DEBUGGED set
```

---

## Section 6: What Each Approach Actually Fixes

| Limitation | Fix Type | Fix Location | Works Without Jailbreak? | Effort |
|---|---|---|---|---|
| Speed (~5–100x slower than native) | W^X JIT via PT_TRACE_ME | `app/AppDelegate.m` (50 lines) | Yes — any sideload method | Low |
| Speed (true RWX JIT) | MAP_JIT + `dynamic-codesigning` | Entitlements + mmap calls | Pre-A12 + TrollStore + iOS ≤16.6.1 only | Low |
| Full JIT backend (ARM64 code emission) | New JIT compiler in `emu/` | Replace Asbestos gadget dispatch | Yes (if built) | Very High (~months) |
| AF_NETLINK missing | Fake netlink in `kernel/sock.c` | `kernel/sock.c` + netlink protocol | Yes | Medium (~700 lines C) |
| `/proc/net/dev` missing | Implement via `getifaddrs()` | `fs/proc/net.c` | Yes | Low-Medium (~150 lines C) |
| `/proc/net/route` missing | Implement via `sysctl(PF_ROUTE)` | `fs/proc/net.c` | Yes | Medium (~200 lines C) |
| `/proc/net/arp` missing | Implement via `sysctl(RTF_LLINFO)` | `fs/proc/net.c` | Yes | Medium (~150 lines C) |
| Raw sockets / `tcpdump` / `nmap -sS` | Cannot implement | N/A | **No** — XNU restriction |N/A |
| Native arm64 Alpine binaries | Cannot implement | N/A | **No** — requires jailbreak | N/A |
| Background execution | `cat /dev/location` keepalive | Already implemented in iSH | Yes | Done |
| Memory limits (~1.5 GB default) | `increased-memory-limit` entitlement | `iSH.entitlements` | Yes (with signing) | Low (1 line) |
| Virtual address space | `extended-virtual-addressing` entitlement | `iSH.entitlements` | Yes (with signing) | Low (1 line) |
| Permanent install (no 7-day expiry) | TrollStore | N/A | Pre-A12 + iOS ≤16.6.1 only | Low |
| Unsandboxed filesystem access | `no-sandbox` entitlement | `iSH.entitlements` | TrollStore only | Low (1 line, dangerous) |

---

## Section 7: Existing Automated Builds

iSH releases automated weekly builds via GitHub Actions. The latest verified builds as of April 2026:

| Build | Date | Commit |
|---|---|---|
| 773 | 12 Apr 2025 | 572e3e8 |
| 772 | 29 Mar 2025 | 35a19ae |
| 771 | 22 Mar 2025 | 5fab9c8 |
| 770 | 15 Mar 2025 | db3dabb |
| 769 | 08 Mar 2025 | 9c96588 |
| 768 | 01 Mar 2025 | c2cfe1e |
| 767 | 22 Feb 2025 | b721a7f |

All builds are tagged as pre-release automated builds. Access them at:

```
https://github.com/ish-app/ish/releases
```

Each release provides 4 assets (typically: IPA, dSYM archive, and source tarballs). **You can download a pre-built IPA and re-sign it** with the `ldid` / `codesign` workflow from Section 5, Step 7 — without building from source.

This is the **fastest path to a custom-entitlement iSH**:
1. Download latest IPA from GitHub Releases
2. Unpack, add entitlements via `ldid` or `codesign`
3. Repack and install via TrollStore / SideStore / Sideloadly

The `PT_TRACE_ME` patch (Section 4) **does** require building from source (or binary patching `AppDelegate` — significantly harder). For StikDebug JIT enablement, you only need the entitlement re-sign — no source build required.

---

## Section 8: CoreTrust / AMFI Chain (How Signing Actually Works)

The full verification chain on iOS for any IPA install:

```
IPA installed to device
        │
        ▼
launchd spawns process via XPC
        │
        ▼
AMFI.kext intercepts execve()
        │
        ├─── Checks binary's Mach-O LC_CODE_SIGNATURE load command
        │    Extracts embedded CMS blob + code directory
        │
        ▼
CoreTrust.framework validates CMS signature
        │
        ├─── Path A: Valid Apple certificate chain
        │    ("App Store Fast Path")
        │    → Any declared entitlements honored
        │    → CS_VALID set, process launches
        │    → Install is permanent
        │
        ├─── Path B: Development certificate (AltStore/Sideloadly)
        │    → get-task-allow honored (development entitlement)
        │    → increased-memory-limit honored (if Apple backend allows it)
        │    → No private entitlements honored
        │    → Expires in 7 days (free) or 1 year (paid)
        │
        └─── Path C: TrollStore CoreTrust bypass
             → Multiple-signer CMS blob exploits CoreTrust bug
             → Binary passes as "system" app
             → ANY declared entitlement honored by AMFI
               EXCEPT PPL-protected ones on A12+:
               - dynamic-codesigning  → CRASH on A12+
               - com.apple.private.cs.debugger  → CRASH on A12+
               - com.apple.private.skip-library-validation  → CRASH on A12+
             → Permanent (no expiry)
```

**PPL (Page Protection Layer) on A12+:**

PPL runs at a higher exception level than even the kernel (it's implemented in a region of memory the kernel cannot write to). Entitlements that require modifying PPL-controlled page table permissions (like `dynamic-codesigning`, which requires simultaneously W+X page mappings) cannot be honored even by TrollStore, because granting them would require the kernel to instruct PPL to create W+X pages — which PPL refuses to do for userland processes without its own internal authorization (which only Apple-blessed processes have).

**TrollStore's CoreTrust bypass technical detail** (credited to @alfiecg_dev and Google TAG):
- Exploits XNU's incorrect handling of CMS signatures where multiple signers are present in a single binary
- Allows a self-signed certificate with `1.2.840.113635.100.6.1.13.1` (App Store extension OID) set
- Results in the binary passing `CoreTrust`'s trust evaluation with an "Apple Distribution" trust chain
- Fixed in iOS 16.7 (final, not RC) and iOS 17.0.1+
- TrollStore 1.x used a different CoreTrust bug found by @LinusHenze; TrollStore 2.x uses the alfiecg_dev / Google TAG bug

---

## Section 9: Recommended Approach by iOS Version

Determine your iOS version first — this drives every other decision.

```bash
# On device, in iSH or any terminal:
sw_vers -productVersion
# Or: cat /System/Library/CoreServices/SystemVersion.plist | grep ProductVersion
```

| Your iOS Version | Best Install Method | JIT Method | Performance vs Baseline | Notes |
|---|---|---|---|---|
| 14.0 – 15.7.x | **TrollStore 2** | A11-: MAP_JIT (true RWX); A12+: W^X via PT_TRACE_ME | A11-: ~10x; A12+: ~3–5x | Best option — permanent, arbitrary entitlements |
| 16.0 – 16.6.1 | **TrollStore 2** | A11-: MAP_JIT; A12+: W^X | A11-: ~10x; A12+: ~3–5x | Same as above |
| 16.7 RC (20H18) | **TrollStore 2** | W^X only (A12+) or MAP_JIT (A11-) | ~3–10x depending on chip | Rare build; check version carefully |
| 16.7.x (non-RC) | **SideStore + StikDebug** | W^X only | ~3–5x | No TrollStore support ever |
| **17.0 exactly** | **TrollStore 2** | W^X only on A12+; MAP_JIT on A11- | ~3–10x | Must be 17.0, not 17.0.1+ |
| 17.0.1 – 17.3.x | **SideStore + SideJITServer** | W^X only | ~3–5x | SideJITServer works here; StikDebug needs 17.4+ |
| 17.4 – 17.x | **SideStore + StikDebug** | W^X only | ~3–5x | StikDebug is the easiest JIT path from 17.4 |
| 18.0 – 18.3.x | **SideStore + StikDebug** | W^X only | ~3–5x | StikDebug confirmed working |
| 18.4+ / iOS 26 | **SideStore + StikDebug** | W^X only (non-TXM hardware) | ~3–5x | TXM on newer hardware limits JIT; older A-series chips unaffected |

**Decision flowchart:**

```
Is your device on iOS 14.0–16.6.1, 16.7 RC, or exactly 17.0?
    │
    ├─ YES → Install TrollStore 2
    │         Is your chip A11 or older?
    │             ├─ YES → Add dynamic-codesigning + allow-jit entitlements
    │             │         → True MAP_JIT (simultaneous RWX, ~10x speedup)
    │             └─ NO  → Add get-task-allow + PT_TRACE_ME in code
    │                       → W^X JIT (~3–5x speedup), permanent
    │
    └─ NO → Install via SideStore or Sideloadly
              Add get-task-allow entitlement
              Is your device running iOS 17.4+?
                  ├─ YES → Install StikDebug, enable JIT after each launch
                  └─ NO  → Use SideJITServer from Mac/PC
              → W^X JIT (~3–5x speedup), 7-day cert refresh
```

**Bottom line — the minimal viable custom iSH build for any iOS version:**

1. Download latest IPA from `https://github.com/ish-app/ish/releases`
2. Add `get-task-allow` + `increased-memory-limit` + `extended-virtual-addressing` via `ldid`
3. Install via SideStore/Sideloadly
4. Enable JIT via StikDebug (iOS 17.4+) or SideJITServer

Result: 3–5x faster iSH, more memory headroom, no source build required, works on any modern iOS.

---

## Sources

- [iSH GitHub Repository](https://github.com/ish-app/ish) — Source code, releases, issues
- [iSH GitHub Issue #145: ip/ifconfig not working, needs netlink](https://github.com/ish-app/ish/issues/145) — AF_NETLINK tracking issue (open since 2018)
- [iSH: JIT, and EU — official iSH blog](https://ish.app/blog/ish-jit-and-eu) — EU DMA filing, Apple's denial, performance numbers
- [TrollStore — opa334/TrollStore](https://github.com/opa334/TrollStore) — Supported iOS versions, banned entitlements, CoreTrust bypass details
- [Jailed Just-in-Time Compilation on iOS — Saagar Jha](https://saagarjha.com/blog/2020/02/23/jailed-just-in-time-compilation-on-ios/) — PT_TRACE_ME technique, CS_DEBUGGED, W^X double-map, signal handling
- [Apple: com.apple.security.cs.allow-jit entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit) — Official entitlement reference
- [StikDebug — StephenDev0/StikDebug](https://github.com/StephenDev0/StikDebug) — On-device JIT enabler
- [SideStore JIT Documentation](https://docs.sidestore.io/docs/advanced/jit) — StikDebug setup, iOS 26 JIT limitations
- [SideJITServer guide — iDevice Central](https://idevicecentral.com/ios-guide/how-to-enable-jit-on-ios-17-0-18-3-using-sidejitserver/) — SideJITServer setup for iOS 17–18.3
- [iSH Interpreter Architecture — Mintlify](https://mintlify.com/Phineas1500/ish/advanced/interpreter) — Asbestos threaded-code internals, gadget system, fiber blocks
