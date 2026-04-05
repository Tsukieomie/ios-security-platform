// emu/jit_helpers.h — C helper functions called from JIT stubs
//
// These handle operations too complex to inline in Phase 2:
//   - Guest memory read/write with full TLB + segfault handling
//   - CALL instruction (push return addr + lookup/translate target)
//   - Complex flag operations (DIV, MUL, etc.)
//
// JIT stubs call these via BLR after flushing live registers to cpu_state.
// Helpers update cpu_state directly and return; stubs reload registers after.

#ifndef EMU_JIT_HELPERS_H
#define EMU_JIT_HELPERS_H

#include "emu/cpu.h"
#include "emu/tlb.h"
#include <stdint.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// Memory helpers — called from JIT when TLB miss or cross-page access
// ---------------------------------------------------------------------------

// Read 32-bit value from guest address. Returns false on segfault.
// On segfault: sets cpu->segfault_addr and cpu->eip = fault_eip.
bool jit_mem_read32(struct cpu_state *cpu, struct tlb *tlb,
                    uint32_t guest_addr, uint32_t *out, uint32_t fault_eip);

// Write 32-bit value to guest address. Returns false on segfault.
bool jit_mem_write32(struct cpu_state *cpu, struct tlb *tlb,
                     uint32_t guest_addr, uint32_t val, uint32_t fault_eip);

// Read 8-bit value from guest address.
bool jit_mem_read8(struct cpu_state *cpu, struct tlb *tlb,
                   uint32_t guest_addr, uint8_t *out, uint32_t fault_eip);

// Write 8-bit value to guest address.
bool jit_mem_write8(struct cpu_state *cpu, struct tlb *tlb,
                    uint32_t guest_addr, uint8_t val, uint32_t fault_eip);

// ---------------------------------------------------------------------------
// Stack helpers — PUSH / POP via guest ESP
// ---------------------------------------------------------------------------

// PUSH a 32-bit value onto the guest stack (ESP -= 4; mem[ESP] = val).
// Returns false on segfault.
bool jit_push32(struct cpu_state *cpu, struct tlb *tlb, uint32_t val);

// POP a 32-bit value from the guest stack (val = mem[ESP]; ESP += 4).
// Returns false on segfault.
bool jit_pop32(struct cpu_state *cpu, struct tlb *tlb, uint32_t *out);

// ---------------------------------------------------------------------------
// CALL helper — push return address, return target EIP
// ---------------------------------------------------------------------------
// Used by translated CALL rel32 / CALL r/m32.
// Pushes return_addr onto guest stack, returns target for JIT dispatch.
// Returns 0 on segfault (cpu->segfault_addr set).
uint32_t jit_do_call(struct cpu_state *cpu, struct tlb *tlb,
                     uint32_t target_eip, uint32_t return_addr);

// ---------------------------------------------------------------------------
// Parity helper — ARM64 has no PF equivalent
// ---------------------------------------------------------------------------
// Returns 1 if parity of low 8 bits of val is even (PF=1), else 0.
static inline int jit_parity(uint32_t val) {
    return !__builtin_parity(val & 0xFF);
}

// ---------------------------------------------------------------------------
// Flag materialisation — compute x86 condition from cpu_state
// Used when NZCV is not live (e.g. Jcc after PUSH/POP/MOV)
// ---------------------------------------------------------------------------
// Returns 1 if the x86 condition (0-15) is true given current cpu_state.
int jit_eval_cc(struct cpu_state *cpu, uint8_t cc);

// ---------------------------------------------------------------------------
// TLB fast-path address computation (inlinable by JIT)
// ---------------------------------------------------------------------------
// Returns host pointer for guest_addr if TLB hit, NULL on miss.
// On miss: caller must call jit_mem_read32 / jit_mem_write32.

static inline void *jit_tlb_read_ptr(struct tlb *tlb, uint32_t addr) {
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    if (__builtin_expect(entry.page == TLB_PAGE(addr), 1))
        return (void *)(entry.data_minus_addr + addr);
    return NULL;
}

static inline void *jit_tlb_write_ptr(struct tlb *tlb, uint32_t addr) {
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    if (__builtin_expect(entry.page_if_writable == TLB_PAGE(addr), 1)) {
        tlb->dirty_page = TLB_PAGE(addr);
        return (void *)(entry.data_minus_addr + addr);
    }
    return NULL;
}

#endif // EMU_JIT_HELPERS_H
