// emu/jit.c — TXM-compliant JIT memory allocator + block cache for iSH
// Target: iPhone 15 Pro (A17 Pro), iOS 26.5, SPTM/TXM
//
// Memory model on TXM (A15+):
//   - W^X enforced at hardware level via SPTM/TXM page table control
//   - MAP_JIT flag allocates a special region TXM is aware of
//   - pthread_jit_write_with_callback_np() atomically switches the current
//     thread's access: RX -> (callback runs, writes code) -> RX again
//   - sys_icache_invalidate() required after every write (ARM i-cache not coherent)
//
// Three conditions must ALL be true for mmap(MAP_JIT) to succeed on A17/iOS 26.5:
//   1. com.apple.security.cs.allow-jit in entitlements
//   2. Development-signed binary (not App Store)
//   3. Debugger attached (StikDebug sets CS_DEBUGGED via GDB RSP over loopback VPN)

#include "emu/jit.h"

#include <sys/mman.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

// sys_icache_invalidate is in libSystem on iOS
extern void sys_icache_invalidate(void *start, size_t len);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#define JIT_REGION_SIZE     (64UL * 1024 * 1024)  // 64 MB code region
#define JIT_MAX_BLOCK_SIZE  (4096)                 // Max ARM64 bytes per block
#define JIT_CACHE_BUCKETS   (1 << 16)              // 65536 hash buckets
#define JIT_ALIGN           16                     // Alignment per block (bytes)

// ---------------------------------------------------------------------------
// JIT region state
// ---------------------------------------------------------------------------

static void   *g_jit_region   = NULL;   // Base of MAP_JIT region
static size_t  g_jit_used     = 0;      // Bump pointer offset
static bool    g_jit_ready    = false;  // Initialised successfully

static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------------------------
// Block cache
// ---------------------------------------------------------------------------

static jit_block_t *g_cache[JIT_CACHE_BUCKETS];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_generation = 0;

// Knuth multiplicative hash — fast, good distribution for EIP values
static inline uint32_t cache_bucket(uint32_t eip) {
    return ((eip * 2654435761u) >> 16) & (JIT_CACHE_BUCKETS - 1);
}

jit_block_t *jit_cache_lookup(uint32_t guest_eip) {
    uint32_t b = cache_bucket(guest_eip);
    // Intentionally no lock on the hot path — reads are safe because:
    // insertions only prepend (never modify existing nodes), and
    // flushes replace the whole bucket pointer atomically.
    jit_block_t *block = atomic_load_explicit(
        (_Atomic(jit_block_t *)*)&g_cache[b], memory_order_acquire);
    while (block) {
        if (block->guest_eip == guest_eip &&
            block->generation == g_generation)
            return block;
        block = block->next;
    }
    return NULL;
}

void jit_cache_insert(jit_block_t *block) {
    block->generation = g_generation;
    uint32_t b = cache_bucket(block->guest_eip);
    pthread_mutex_lock(&g_cache_lock);
    block->next = g_cache[b];
    // Store with release so other threads see the full block before the pointer
    atomic_store_explicit((_Atomic(jit_block_t *)*)&g_cache[b],
                          block, memory_order_release);
    pthread_mutex_unlock(&g_cache_lock);
}

void jit_cache_flush_all(void) {
    pthread_mutex_lock(&g_cache_lock);
    // Bump generation — existing blocks become invisible to lookup
    // (we don't free them individually; the bump allocator resets)
    g_generation++;
    // Zero out all bucket heads
    memset(g_cache, 0, sizeof(g_cache));
    // Reset bump allocator
    g_jit_used = 0;
    pthread_mutex_unlock(&g_cache_lock);
}

void jit_cache_invalidate_range(uint32_t start, uint32_t end) {
    pthread_mutex_lock(&g_cache_lock);
    // Walk all buckets — O(N) but only called on self-modifying code
    for (int b = 0; b < JIT_CACHE_BUCKETS; b++) {
        jit_block_t **pp = &g_cache[b];
        jit_block_t *block = *pp;
        while (block) {
            jit_block_t *next = block->next;
            if (block->guest_eip >= start && block->guest_eip < end) {
                *pp = next;
                free(block);
            } else {
                pp = &block->next;
            }
            block = next;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
}

// ---------------------------------------------------------------------------
// TXM-compliant JIT write callback
// ---------------------------------------------------------------------------
// This function MUST be registered with PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP.
// TXM validates that it is in the allowlist before making the JIT region
// writable for the calling thread.

typedef struct {
    void       *dest;   // Destination in JIT region
    const void *src;    // Source ARM64 code buffer
    size_t      size;   // Bytes to copy
} jit_write_ctx_t;

static int jit_write_callback(void *ctx_raw) {
    jit_write_ctx_t *ctx = (jit_write_ctx_t *)ctx_raw;
    memcpy(ctx->dest, ctx->src, ctx->size);
    return 0;
}

// Register the callback in the allowlist.
// MUST appear exactly ONCE per executable, at file scope.
// This macro inserts a linker section entry that TXM reads at process launch.
PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP(jit_write_callback);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool jit_is_available(void) {
    return g_jit_ready;
}

int jit_init(void) {
    if (g_jit_ready) return 0;  // Already initialised

    // mmap(MAP_JIT) requires:
    //   - com.apple.security.cs.allow-jit entitlement
    //   - CS_DEBUGGED set (StikDebug attached)
    //   - TXM running (A15+, iOS 17+) validates both conditions
    //
    // On success: returns a region that is PROT_READ|PROT_EXEC.
    // Writes go via pthread_jit_write_with_callback_np() only.
    g_jit_region = mmap(
        NULL,
        JIT_REGION_SIZE,
        PROT_READ | PROT_EXEC,          // Initial perms: RX (no write)
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
        -1, 0
    );

    if (g_jit_region == MAP_FAILED) {
        g_jit_region = NULL;
        fprintf(stderr,
            "[iSH-JIT] mmap(MAP_JIT) failed: %s\n"
            "[iSH-JIT] Is StikDebug attached? Falling back to Asbestos.\n",
            strerror(errno));
        return -1;
    }

    g_jit_used  = 0;
    g_jit_ready = true;
    fprintf(stderr,
        "[iSH-JIT] Initialised. Region %p, size %lu MB.\n",
        g_jit_region, JIT_REGION_SIZE / 1024 / 1024);
    return 0;
}

void jit_shutdown(void) {
    if (!g_jit_region) return;
    munmap(g_jit_region, JIT_REGION_SIZE);
    g_jit_region = NULL;
    g_jit_ready  = false;
    jit_cache_flush_all();
}

void *jit_emit(const uint32_t *insns, size_t count) {
    if (!g_jit_ready || !insns || count == 0)
        return NULL;

    size_t size = count * sizeof(uint32_t);
    assert(size <= JIT_MAX_BLOCK_SIZE);

    pthread_mutex_lock(&g_alloc_lock);

    // If we've run out of space, flush everything and wrap around.
    // This is the simplest eviction policy; a future version can do LRU.
    if (g_jit_used + size > JIT_REGION_SIZE) {
        fprintf(stderr, "[iSH-JIT] Cache full — flushing all blocks.\n");
        jit_cache_flush_all();  // Acquires g_cache_lock internally
        // g_jit_used is now 0 after flush
    }

    void *dest = (uint8_t *)g_jit_region + g_jit_used;

    // Write ARM64 code via TXM-authorised callback.
    // pthread_jit_write_with_callback_np():
    //   1. Verifies jit_write_callback is in the allowlist
    //   2. Switches this thread's JIT region perms: RX -> RW (not executable)
    //   3. Calls jit_write_callback(&ctx) — our memcpy runs here
    //   4. Switches back: RW -> RX (not writable)
    jit_write_ctx_t ctx = { .dest = dest, .src = insns, .size = size };
    int rc = pthread_jit_write_with_callback_np(jit_write_callback, &ctx);
    if (rc != 0) {
        pthread_mutex_unlock(&g_alloc_lock);
        fprintf(stderr, "[iSH-JIT] pthread_jit_write_with_callback_np failed: %d\n", rc);
        return NULL;
    }

    // CRITICAL on Apple Silicon: i-cache is NOT coherent with d-cache.
    // Must invalidate before executing freshly written code.
    sys_icache_invalidate(dest, size);

    // Advance bump pointer, aligned to JIT_ALIGN bytes
    g_jit_used += size;
    g_jit_used  = (g_jit_used + JIT_ALIGN - 1) & ~(size_t)(JIT_ALIGN - 1);

    pthread_mutex_unlock(&g_alloc_lock);
    return dest;
}

// ---------------------------------------------------------------------------
// Execution loop hook
// ---------------------------------------------------------------------------

bool jit_run_block(struct cpu_state *cpu, struct tlb *tlb) {
    if (!g_jit_ready) return false;

    uint32_t eip = cpu->eip;

    // Cache lookup — no lock on hot path (see jit_cache_lookup comment)
    jit_block_t *block = jit_cache_lookup(eip);

    if (!block) {
        // Translate this basic block
        block = jit_translate(eip, tlb, cpu);
        if (!block) return false;
        jit_cache_insert(block);
    }

    // Execute: cast host_code pointer to a C function and call it.
    // The translated ARM64 stub takes (cpu_state *) and updates cpu->eip.
    typedef void (*jit_stub_t)(struct cpu_state *);
    jit_stub_t fn = (jit_stub_t)block->host_code;
    fn(cpu);

    return true;
}

// ---------------------------------------------------------------------------
// Debug statistics
// ---------------------------------------------------------------------------

#ifdef DEBUG
jit_stats_t g_jit_stats = {0};

void jit_print_stats(void) {
    fprintf(stderr,
        "[iSH-JIT] cache_hits=%llu misses=%llu blocks=%llu "
        "insns_jit=%llu insns_fallback=%llu emit_failures=%llu\n",
        (unsigned long long)g_jit_stats.cache_hits,
        (unsigned long long)g_jit_stats.cache_misses,
        (unsigned long long)g_jit_stats.blocks_translated,
        (unsigned long long)g_jit_stats.insns_translated,
        (unsigned long long)g_jit_stats.insns_fallback,
        (unsigned long long)g_jit_stats.emit_failures);
}
#endif
