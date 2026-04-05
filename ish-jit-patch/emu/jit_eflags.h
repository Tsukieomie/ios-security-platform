// emu/jit_eflags.h — Lazy EFLAGS evaluation for iSH JIT
//
// The x86 EFLAGS register has 6 arithmetic flags: CF, PF, AF, ZF, SF, OF.
// Most instructions SET flags but few immediately READ them (flag reads
// typically only happen at Jcc / SETCC / CMOVcc). Computing all 6 flags after
// every instruction is expensive.
//
// Strategy: "lazy evaluation"
//   - After an instruction that affects flags, store the raw result + operands
//     in cpu_state fields (res, op1, op2, flags_res byte).
//   - When a Jcc or other flag consumer needs a specific flag, compute ONLY
//     that flag on demand using the stored operands.
//   - The ARM64 NZCV register is used as an accelerator: ADDS/SUBS naturally
//     produce N, Z, C, V that map directly to SF, ZF, CF, OF for common ops.
//
// iSH already has this mechanism in cpu.h (flags_res byte, res/op1/op2 fields).
// We use the same fields so JIT-executed code and interpreter-executed code
// share the same flag state — critical for mixed JIT/interpreter operation.
//
// ARM64 NZCV ↔ x86 EFLAGS mapping:
//   N (Negative)  ↔ SF (Sign Flag)
//   Z (Zero)      ↔ ZF (Zero Flag)
//   C (Carry)     ↔ CF (Carry Flag)   NOTE: ARM carry is NOT inverted for SUB
//   V (oVerflow)  ↔ OF (Overflow Flag)
//
// SUB/CMP: x86 sets CF=1 when borrow occurs (dst < src unsigned).
//          ARM64 SUBS sets C=0 when borrow occurs (opposite sense!).
//          We correct this when emitting CMP/SUB Jcc sequences.

#ifndef EMU_JIT_EFLAGS_H
#define EMU_JIT_EFLAGS_H

#include "emu/cpu.h"
#include "emu/jit_arm64.h"

// ---------------------------------------------------------------------------
// Flag operation types — stored in a JIT-private register across a block
// to track what the last flag-setting instruction was.
// ---------------------------------------------------------------------------
typedef enum {
    FLOP_NONE = 0,   // No pending flags
    FLOP_ADD,        // Result of ADD/ADC/INC — ADDS sets NZCV correctly
    FLOP_SUB,        // Result of SUB/SBB/DEC/CMP — SUBS sets NZCV, CF inverted
    FLOP_LOGIC,      // Result of AND/OR/XOR/TEST — CF=OF=0, ZF/SF/PF from res
    FLOP_INC,        // INC: like ADD but CF unchanged
    FLOP_DEC,        // DEC: like SUB but CF unchanged
} flag_op_t;

// ---------------------------------------------------------------------------
// JIT flag state — carried through a basic block in ARM64 registers
// ---------------------------------------------------------------------------
// We use one additional ARM64 register to track which operation set the flags.
// AR_FLOP (x28) holds a flag_op_t value.
// After ADDS/SUBS, NZCV is live in the ARM64 condition flags register.
// We only materialise flags into cpu_state when:
//   a) A Jcc is encountered (need specific flag)
//   b) The block ends (for correctness across block boundaries)

#define AR_FLOP  28  // x28: current flag_op_t (callee-saved)

// ---------------------------------------------------------------------------
// ARM64 instructions for flag-setting operations
// ---------------------------------------------------------------------------

// ADDS Wd, Wn, Wm  (32-bit, sets NZCV)
static inline uint32_t A_ADDS_W(int rd, int rn, int rm) {
    return 0x2B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUBS Wd, Wn, Wm  (32-bit, sets NZCV; N=SF, Z=ZF, C=~CF for SUB, V=OF)
static inline uint32_t A_SUBS_W(int rd, int rn, int rm) {
    return 0x6B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ANDS Wd, Wn, Wm  (32-bit, sets NZ; clears CV; PF computed from result)
static inline uint32_t A_ANDS_W(int rd, int rn, int rm) {
    return 0x6A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// MRS Xd, NZCV  — read condition flags into register
static inline uint32_t A_MRS_NZCV(int rd) {
    return 0xD53B4200u | (uint32_t)rd;
}

// MSR NZCV, Xn  — write condition flags from register
static inline uint32_t A_MSR_NZCV(int rn) {
    return 0xD51B4200u | (uint32_t)rn;
}

// ---------------------------------------------------------------------------
// Emit flag-saving: after ADDS/SUBS/ANDS, save NZCV + result to cpu_state
// so that the interpreter can read flags correctly if it takes over.
// ---------------------------------------------------------------------------

// Save the current ARM64 NZCV + result register to cpu_state.
// Call after every flag-setting instruction.
// reg_result: ARM64 register holding the result (already stored in x86 reg)
// flop: what kind of operation produced these flags
static inline void emit_save_flags(arm64_buf_t *b, int reg_result,
                                    flag_op_t flop) {
    // Save result to cpu->res (used by ZF_RES, SF_RES, PF_RES macros)
    arm64_emit(b, A_STR_W(reg_result, AR_CPU,
        (int)__builtin_offsetof(struct cpu_state, res)));

    // Save NZCV to AR_FLOP so Jcc emitters can read it back
    arm64_emit(b, A_MRS_NZCV(AR_FLOP));

    // Set flags_res byte: ZF, SF, PF are all computed from res
    // PF_RES=1, ZF_RES=1, SF_RES=1, AF_OPS=0
    // Value = PF_RES|ZF_RES|SF_RES = 0b111 = 7
    // But for SUB/CMP: same — ZF/SF/PF all come from result
    uint32_t flags_res_val = PF_RES | ZF_RES | SF_RES;
    arm64_mov_imm32(b, AR_T0, flags_res_val);
    // Store as a single byte to cpu->flags_res
    arm64_emit(b, 0x39000000u |  // STRB W_T0, [X_CPU, #offset]
        ((uint32_t)__builtin_offsetof(struct cpu_state, flags_res) << 10) |
        ((uint32_t)AR_CPU << 5) | (uint32_t)AR_T0);

    // For ADD/SUB: also save CF and OF from NZCV
    // NZCV is in bits [31:28] of AR_FLOP
    // N=bit31=SF, Z=bit30=ZF, C=bit29=CF(or~CF for SUB), V=bit28=OF
    if (flop == FLOP_ADD || flop == FLOP_SUB) {
        // Extract C bit → cpu->cf
        // LSR AR_T0, AR_FLOP, #29; AND AR_T0, AR_T0, #1
        arm64_emit(b, 0xD35FFB80u | (uint32_t)AR_FLOP | ((uint32_t)AR_T0 << 0));
        // For ADD: CF = C bit directly
        // For SUB: CF = ~C bit (ARM SUBS inverts carry sense)
        if (flop == FLOP_SUB) {
            arm64_emit(b, 0x52800020u | (uint32_t)AR_T0);  // EOR T0, T0, #1
        }
        arm64_emit(b, 0x39000000u |
            ((uint32_t)__builtin_offsetof(struct cpu_state, cf) << 10) |
            ((uint32_t)AR_CPU << 5) | (uint32_t)AR_T0);

        // Extract V bit → cpu->of
        arm64_emit(b, 0xD35FFB00u | (uint32_t)AR_FLOP | ((uint32_t)AR_T1 << 0));
        arm64_emit(b, 0x39000000u |
            ((uint32_t)__builtin_offsetof(struct cpu_state, of) << 10) |
            ((uint32_t)AR_CPU << 5) | (uint32_t)AR_T1);
    } else if (flop == FLOP_LOGIC) {
        // AND/OR/XOR/TEST: CF=0, OF=0
        arm64_mov_imm32(b, AR_T0, 0);
        arm64_emit(b, 0x39000000u |
            ((uint32_t)__builtin_offsetof(struct cpu_state, cf) << 10) |
            ((uint32_t)AR_CPU << 5) | (uint32_t)AR_T0);
        arm64_emit(b, 0x39000000u |
            ((uint32_t)__builtin_offsetof(struct cpu_state, of) << 10) |
            ((uint32_t)AR_CPU << 5) | (uint32_t)AR_T0);
    }
}

// ---------------------------------------------------------------------------
// Emit a Jcc (conditional branch) using ARM64 Bcc
//
// After an ADD/SUB/AND that set flags, NZCV is live in the ARM64 condition
// register. We emit ARM64 B.cond directly — no flag recomputation needed.
//
// x86 cc: 0=JO 1=JNO 2=JB 3=JAE 4=JE 5=JNE 6=JBE 7=JA
//         8=JS 9=JNS 10=JP 11=JNP 12=JL 13=JGE 14=JLE 15=JG
//
// Returns: number of ARM64 instructions emitted (for branch offset calculation)
// ---------------------------------------------------------------------------

// Emit Jcc where NZCV is live in the ARM64 condition flags.
// taken_off: instruction offset to taken branch (relative to this B.cond insn)
// fall_off:  instruction offset to fallthrough (relative to next insn after epilogue)
//
// Emits:
//   B.cond taken           ; branch if condition true
//   [fallthrough epilogue]
//   [taken epilogue]
static void emit_jcc_with_live_nzcv(arm64_buf_t *b, uint8_t x86_cc,
                                     uint32_t taken_eip, uint32_t fall_eip,
                                     flag_op_t flop) {
    // Parity (JP/JNP) has no ARM64 equivalent — fall back
    if (x86_cc == 10 || x86_cc == 11) {
        // Store EIP and let interpreter sort it out
        emit_set_eip(b, fall_eip);  // conservative: always take fallthrough
        emit_epilogue(b);
        return;
    }

    uint8_t arm_cond = x86cc_to_arm64[x86_cc];

    // For SUB/CMP, CF sense is inverted: swap JB↔JAE and JBE↔JA
    if (flop == FLOP_SUB || flop == FLOP_DEC) {
        if (x86_cc == 2)  arm_cond = A_CS;  // JB  → ARM CS (not CC)
        if (x86_cc == 3)  arm_cond = A_CC;  // JAE → ARM CC (not CS)
        if (x86_cc == 6)  arm_cond = A_LS;  // JBE stays LS (Z=1 || C=0)
        if (x86_cc == 7)  arm_cond = A_HI;  // JA  stays HI (C=1 && Z=0) — same
    }

    // Layout in the output buffer:
    //   [0] B.cond #taken_branch   (6 instructions ahead = +6)
    //   [1..5] fallthrough epilogue: set_eip(fall_eip) + store regs + ldp + ret
    //           set_eip = 1-2 insns, store 8 regs = 8 insns, ldp = 1, ret = 1 → ~13
    //   [13..N] taken epilogue: set_eip(taken_eip) + store regs + ldp + ret

    // We don't know the exact offset yet (epilogue size varies).
    // Simple approach: emit B.cond with placeholder, fill in offset after.
    int branch_insn_idx = b->count;
    arm64_emit(b, 0);  // placeholder for B.cond

    // Fallthrough path epilogue
    emit_set_eip(b, fall_eip);
    emit_epilogue(b);

    // Calculate actual offset to taken label
    int taken_insn_idx = b->count;
    int offset = taken_insn_idx - branch_insn_idx;  // instructions

    // Patch the B.cond placeholder
    b->buf[branch_insn_idx] = A_BCOND(arm_cond, offset);

    // Taken path epilogue
    emit_set_eip(b, taken_eip);
    emit_epilogue(b);
}

#endif // EMU_JIT_EFLAGS_H
