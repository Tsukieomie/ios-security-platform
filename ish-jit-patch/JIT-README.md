# iSH JIT Backend — Phase 1

TXM-compliant JIT for iPhone 15 Pro (A17 Pro), iOS 26.5.

## What This Is

A JIT compilation backend added to iSH that replaces the Asbestos gadget
interpreter with native ARM64 code generation for common x86 instructions.

On A17 Pro (and all A15+), Apple's SPTM/TXM enforces hardware W^X. This
implementation uses the only compliant path: `mmap(MAP_JIT)` +
`pthread_jit_write_with_callback_np()`, activated by StikDebug's debugger
attachment which sets `CS_DEBUGGED`.

## New Files

| File | Purpose |
|---|---|
| `emu/jit.h` | Public API: init, cache lookup/insert, emit, run |
| `emu/jit.c` | TXM-compliant allocator, block cache (Knuth hash, bump alloc) |
| `emu/jit_arm64.h` | ARM64 encoding helpers + register mapping |
| `emu/jit_arm64.c` | x86→ARM64 basic block translator |

## Changed Files

| File | Change |
|---|---|
| `app/iSH.entitlements` | Added `allow-jit`, `jit-write-allowlist`, `get-task-allow`, memory entitlements |
| `app/AppDelegate.m` | Added `jit_wait_and_init()` — polls CS_DEBUGGED, calls `jit_init()` |
| `meson.build` | Added `jit.c` + `jit_arm64.c` to `emu_src` |

## How to Build

```bash
git clone --recurse-submodules https://github.com/Tsukieomie/ios-security-platform
# Open ish-jit as a sub-project in Xcode, or use the upstream iSH.xcodeproj
# Add these files to the Xcode project:
#   emu/jit.c, emu/jit_arm64.c
# Replace iSH.entitlements with the patched version
```

## How to Use (iPhone 15 Pro / iOS 26.5)

1. Build and sideload via **SideStore** (signs with dev cert, 7-day expiry)
2. Install **StikDebug** from App Store (or sideload)
3. Open **LocalDevVPN** → enable VPN
4. Open iSH — it boots immediately via Asbestos interpreter
5. Open StikDebug → **Connect by App** → select iSH
6. Within 200ms, iSH detects `CS_DEBUGGED` and calls `jit_init()`
7. `mmap(MAP_JIT)` succeeds — JIT region allocated (64MB)
8. From this point, translated basic blocks run as native ARM64

Check Xcode console for:
```
[iSH-JIT] CS_DEBUGGED set (attempt N). Initialising JIT.
[iSH-JIT] MAP_JIT succeeded. JIT active on A17/TXM.
[iSH-JIT] Initialised. Region 0x..., size 64 MB.
```

## Phase 1 Coverage

Translated instructions (register-to-register forms):

| Group | Instructions |
|---|---|
| Data move | MOV r,r / MOV r,imm32 / XCHG |
| Arithmetic | ADD, SUB, INC, DEC |
| Logic | AND, OR, XOR, NOT |
| Compare | CMP, TEST |
| Branch | JMP rel8/rel32 |
| No-op | NOP, XCHG EAX,EAX |

Memory operands, PUSH/POP, CALL, RET, Jcc, FPU → fall back to Asbestos.
Fallback is correct and transparent — mixed JIT/interpreter operation is safe.

## Phase 2 (next)

- Inline PUSH/POP via TLB fast path
- Inline RET (pop + branch)
- Lazy EFLAGS (defer CF/OF/ZF/SF/PF until flags are read)
- Jcc with ARM64 Bcc (requires lazy flags)
- CALL with JIT cache lookup
- Memory operand forms of MOV, ADD, etc.

## Architecture Notes

### TXM Memory Model

```
PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP(jit_write_callback)
    ↓ registered at link time (TXM reads this section at process launch)

jit_emit(insns, count):
    pthread_jit_write_with_callback_np(jit_write_callback, &ctx)
        ↓ TXM: switch this thread's JIT region perms: RX → RW
        jit_write_callback: memcpy(dest, src, size)
        ↓ TXM: switch back: RW → RX
    sys_icache_invalidate(dest, size)   ← mandatory on ARM
    return dest                          ← executable pointer
```

### Block Cache

- 65536 buckets, Knuth multiplicative hash on guest EIP
- Lockless read path (`memory_order_acquire` on bucket head)
- Locked insert path (prepend to chain)
- Flush = bump generation counter + memset buckets + reset allocator

### Register Mapping

```
x19 = struct cpu_state *cpu   (live throughout block, callee-saved)
x20 = EAX    x21 = ECX    x22 = EDX    x23 = EBX
x24 = ESP    x25 = EBP    x26 = ESI    x27 = EDI
x0-x4 = scratch (caller-saved, used for temporaries)
```

## Performance Expectation

Phase 1 accelerates only register-to-register code. Real workloads hit memory
operands often, so measured speedup will be modest (~1.2-1.5x) until Phase 2
adds memory access inlining and lazy flags.
