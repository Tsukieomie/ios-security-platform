// emu/jit.h — iSH JIT backend public interface
// Target: iPhone 15 Pro (A17 Pro), iOS 26.5, SPTM/TXM
//
// Requires in iSH.entitlements:
//   com.apple.security.cs.allow-jit
//   com.apple.security.cs.jit-write-allowlist
//   get-task-allow
//
// Requires StikDebug attached (sets CS_DEBUGGED) for MAP_JIT to succeed on TXM.

#ifndef EMU_JIT_H
#define EMU_JIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "emu/cpu.h"
#include "emu/tlb.h"

// ---------------------------------------------------------------------------
// JIT availability
// ---------------------------------------------------------------------------

// Returns true if the JIT region was successfully allocated.
// Call jit_init() first. If this returns false, Asbestos interpreter is used.
bool jit_is_available(void);

// Initialise the JIT subsystem. Safe to call multiple times — only acts once.
// Must be called AFTER StikDebug has attached (CS_DEBUGGED must be set).
// Returns 0 on success, -1 if MAP_JIT fails.
int jit_init(void);

// Tear down — frees JIT region and block cache. Called on process exit.
void jit_shutdown(void);

// ---------------------------------------------------------------------------
// Block cache
// ---------------------------------------------------------------------------

// One translated basic block: maps a guest x86 EIP to ARM64 host code.
typedef struct jit_block {
    uint32_t         guest_eip;   // x86 guest address (lookup key)
    void            *host_code;   // pointer into JIT region (ARM64, executable)
    uint32_t         host_size;   // bytes of ARM64 code
    uint32_t         generation;  // cache generation (for bulk invalidation)
    struct jit_block *next;       // hash chain
} jit_block_t;

// Look up a block by guest EIP. Returns NULL on cache miss.
jit_block_t *jit_cache_lookup(uint32_t guest_eip);

// Insert a newly translated block into the cache.
void jit_cache_insert(jit_block_t *block);

// Invalidate all cached blocks (e.g. after self-modifying code is detected).
void jit_cache_flush_all(void);

// Invalidate all blocks whose guest code overlaps [start, end).
void jit_cache_invalidate_range(uint32_t start, uint32_t end);

// ---------------------------------------------------------------------------
// Code emission
// ---------------------------------------------------------------------------

// Write ARM64 instructions into the JIT region using TXM-compliant callback.
// insns: array of uint32_t ARM64 words, count: number of instructions.
// Returns a pointer to the executable code, or NULL on failure.
// Caller must NOT write to the returned pointer directly — use jit_emit().
void *jit_emit(const uint32_t *insns, size_t count);

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

// Translate the x86 basic block starting at guest_eip.
// Reads guest memory via tlb. Returns a jit_block_t (not yet cached),
// or NULL if translation fails or the block is too long.
jit_block_t *jit_translate(uint32_t guest_eip, struct tlb *tlb,
                            struct cpu_state *cpu);

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// Execute one basic block via JIT. Updates cpu->eip on exit.
// Returns false if JIT is unavailable or the block can't be translated
// (caller should fall back to Asbestos for one instruction).
bool jit_run_block(struct cpu_state *cpu, struct tlb *tlb);

// ---------------------------------------------------------------------------
// Statistics (debug builds only)
// ---------------------------------------------------------------------------

#ifdef DEBUG
typedef struct {
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t blocks_translated;
    uint64_t insns_translated;
    uint64_t insns_fallback;   // fell back to interpreter
    uint64_t emit_failures;
} jit_stats_t;

extern jit_stats_t g_jit_stats;
void jit_print_stats(void);
#endif

#endif // EMU_JIT_H
