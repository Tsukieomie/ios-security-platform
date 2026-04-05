// emu/jit_helpers.c — C helpers called from JIT stubs

#include "emu/jit_helpers.h"
#include "emu/cpu.h"
#include "emu/tlb.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Memory helpers
// ---------------------------------------------------------------------------

bool jit_mem_read32(struct cpu_state *cpu, struct tlb *tlb,
                    uint32_t guest_addr, uint32_t *out, uint32_t fault_eip) {
    if (!tlb_read(tlb, guest_addr, out, 4)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->eip = fault_eip;
        return false;
    }
    return true;
}

bool jit_mem_write32(struct cpu_state *cpu, struct tlb *tlb,
                     uint32_t guest_addr, uint32_t val, uint32_t fault_eip) {
    if (!tlb_write(tlb, guest_addr, &val, 4)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->eip = fault_eip;
        return false;
    }
    return true;
}

bool jit_mem_read8(struct cpu_state *cpu, struct tlb *tlb,
                   uint32_t guest_addr, uint8_t *out, uint32_t fault_eip) {
    if (!tlb_read(tlb, guest_addr, out, 1)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->eip = fault_eip;
        return false;
    }
    return true;
}

bool jit_mem_write8(struct cpu_state *cpu, struct tlb *tlb,
                    uint32_t guest_addr, uint8_t val, uint32_t fault_eip) {
    if (!tlb_write(tlb, guest_addr, &val, 1)) {
        cpu->segfault_addr = tlb->segfault_addr;
        cpu->eip = fault_eip;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------

bool jit_push32(struct cpu_state *cpu, struct tlb *tlb, uint32_t val) {
    cpu->esp -= 4;
    if (!tlb_write(tlb, cpu->esp, &val, 4)) {
        // Segfault: undo ESP change
        cpu->esp += 4;
        cpu->segfault_addr = tlb->segfault_addr;
        return false;
    }
    return true;
}

bool jit_pop32(struct cpu_state *cpu, struct tlb *tlb, uint32_t *out) {
    if (!tlb_read(tlb, cpu->esp, out, 4)) {
        cpu->segfault_addr = tlb->segfault_addr;
        return false;
    }
    cpu->esp += 4;
    return true;
}

// ---------------------------------------------------------------------------
// CALL helper
// ---------------------------------------------------------------------------

uint32_t jit_do_call(struct cpu_state *cpu, struct tlb *tlb,
                     uint32_t target_eip, uint32_t return_addr) {
    if (!jit_push32(cpu, tlb, return_addr)) {
        return 0;  // Segfault
    }
    return target_eip;
}

// ---------------------------------------------------------------------------
// Condition evaluation (when NZCV is not live)
// ---------------------------------------------------------------------------

int jit_eval_cc(struct cpu_state *cpu, uint8_t cc) {
    // Use the same macros as iSH's interpreter
    int zf = ZF, sf = SF, cf = CF, of = OF;
    // PF is expensive; compute only if needed
    switch (cc) {
    case 0:  return of;               // JO
    case 1:  return !of;              // JNO
    case 2:  return cf;               // JB / JC
    case 3:  return !cf;              // JAE / JNC
    case 4:  return zf;               // JE / JZ
    case 5:  return !zf;              // JNE / JNZ
    case 6:  return cf || zf;         // JBE
    case 7:  return !cf && !zf;       // JA
    case 8:  return sf;               // JS
    case 9:  return !sf;              // JNS
    case 10: return jit_parity(cpu->res);   // JP
    case 11: return !jit_parity(cpu->res);  // JNP
    case 12: return sf != of;         // JL
    case 13: return sf == of;         // JGE
    case 14: return zf || (sf != of); // JLE
    case 15: return !zf && (sf == of);// JG
    default: return 0;
    }
}
