// emu/jit_arm64.h — ARM64 instruction encoding helpers + x86→ARM64 translator
// All encodings produce little-endian uint32_t words (ARM64 fixed-width).

#ifndef EMU_JIT_ARM64_H
#define EMU_JIT_ARM64_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "emu/cpu.h"
#include "emu/tlb.h"
#include "emu/jit.h"

// ---------------------------------------------------------------------------
// Output buffer
// ---------------------------------------------------------------------------

#define JIT_BUF_MAX 1024  // Max ARM64 instructions per translated block

typedef struct {
    uint32_t buf[JIT_BUF_MAX];
    int      count;           // Instructions emitted so far
    bool     overflow;        // Set if count would exceed JIT_BUF_MAX
} arm64_buf_t;

static inline void arm64_buf_init(arm64_buf_t *b) {
    b->count    = 0;
    b->overflow = false;
}

static inline void arm64_emit(arm64_buf_t *b, uint32_t insn) {
    if (b->count < JIT_BUF_MAX) {
        b->buf[b->count++] = insn;
    } else {
        b->overflow = true;
    }
}

// ---------------------------------------------------------------------------
// Register assignments
// ---------------------------------------------------------------------------
// We dedicate callee-saved ARM64 registers to hold the cpu_state pointer and
// the 8 x86 general-purpose registers throughout a basic block.
// This avoids repeated loads/stores to cpu_state on every instruction.

#define AR_CPU  19   // x19 = struct cpu_state *cpu (callee-saved, always live)
#define AR_EAX  20   // x20 = cpu->eax
#define AR_ECX  21   // x21 = cpu->ecx
#define AR_EDX  22   // x22 = cpu->edx
#define AR_EBX  23   // x23 = cpu->ebx
#define AR_ESP  24   // x24 = cpu->esp
#define AR_EBP  25   // x25 = cpu->ebp
#define AR_ESI  26   // x26 = cpu->esi
#define AR_EDI  27   // x27 = cpu->edi

// Scratch registers — not preserved across calls
#define AR_T0   0
#define AR_T1   1
#define AR_T2   2
#define AR_T3   3
#define AR_T4   4

// Mapping: x86 reg index (0=EAX..7=EDI) → ARM64 register number
static const int x86reg_to_arm64[8] = {
    AR_EAX, AR_ECX, AR_EDX, AR_EBX,
    AR_ESP, AR_EBP, AR_ESI, AR_EDI
};

// Byte offset of regs[i] in struct cpu_state
static inline int cpu_reg_offset(int reg_idx) {
    return (int)__builtin_offsetof(struct cpu_state, regs) + reg_idx * 4;
}

// ---------------------------------------------------------------------------
// ARM64 instruction encoders
// All use 64-bit register variants (Xn) except where noted.
// ---------------------------------------------------------------------------

// MOV Xd, Xn
static inline uint32_t A_MOV_R(int rd, int rn) {
    return 0xAA0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}

// MOV Wd, Wn  (32-bit)
static inline uint32_t A_MOV_W(int rd, int rn) {
    return 0x2A0003E0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}

// MOVZ Xd, #imm16, LSL #shift  (shift = 0, 16, 32, 48)
static inline uint32_t A_MOVZ(int rd, uint16_t imm, int shift) {
    return 0xD2800000u | ((uint32_t)(shift/16) << 21) |
           ((uint32_t)imm << 5) | (uint32_t)rd;
}

// MOVK Xd, #imm16, LSL #shift  (keep other bits)
static inline uint32_t A_MOVK(int rd, uint16_t imm, int shift) {
    return 0xF2800000u | ((uint32_t)(shift/16) << 21) |
           ((uint32_t)imm << 5) | (uint32_t)rd;
}

// Emit a 32-bit immediate into rd (uses MOVZ + optional MOVK)
static inline void arm64_mov_imm32(arm64_buf_t *b, int rd, uint32_t imm) {
    arm64_emit(b, A_MOVZ(rd, (uint16_t)(imm & 0xFFFF), 0));
    if (imm >> 16)
        arm64_emit(b, A_MOVK(rd, (uint16_t)(imm >> 16), 16));
}

// ADD Xd, Xn, Xm
static inline uint32_t A_ADD_R(int rd, int rn, int rm) {
    return 0x8B000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADD Xd, Xn, #imm12 (unsigned 12-bit, no shift)
static inline uint32_t A_ADD_I(int rd, int rn, uint16_t imm) {
    return 0x91000000u | ((uint32_t)(imm & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ADDS Xd, Xn, Xm  (sets NZCV flags)
static inline uint32_t A_ADDS_R(int rd, int rn, int rm) {
    return 0xAB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Xd, Xn, Xm
static inline uint32_t A_SUB_R(int rd, int rn, int rm) {
    return 0xCB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUB Xd, Xn, #imm12
static inline uint32_t A_SUB_I(int rd, int rn, uint16_t imm) {
    return 0xD1000000u | ((uint32_t)(imm & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// SUBS Xd, Xn, Xm  (sets NZCV)
static inline uint32_t A_SUBS_R(int rd, int rn, int rm) {
    return 0xEB000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// AND Xd, Xn, Xm
static inline uint32_t A_AND_R(int rd, int rn, int rm) {
    return 0x8A000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ANDS Xd, Xn, Xm  (sets NZCV)
static inline uint32_t A_ANDS_R(int rd, int rn, int rm) {
    return 0xEA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// ORR Xd, Xn, Xm
static inline uint32_t A_ORR_R(int rd, int rn, int rm) {
    return 0xAA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// EOR Xd, Xn, Xm
static inline uint32_t A_EOR_R(int rd, int rn, int rm) {
    return 0xCA000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

// MVN Xd, Xm  (bitwise NOT)
static inline uint32_t A_MVN_R(int rd, int rm) {
    return 0xAA2003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}

// LDR Wd, [Xn, #imm12*4]  (32-bit load, unsigned offset scaled by 4)
static inline uint32_t A_LDR_W(int rd, int rn, int byte_off) {
    return 0xB9400000u | (((uint32_t)(byte_off/4) & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STR Wd, [Xn, #imm12*4]  (32-bit store)
static inline uint32_t A_STR_W(int rd, int rn, int byte_off) {
    return 0xB9000000u | (((uint32_t)(byte_off/4) & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// LDR Xd, [Xn, #imm12*8]  (64-bit load)
static inline uint32_t A_LDR_X(int rd, int rn, int byte_off) {
    return 0xF9400000u | (((uint32_t)(byte_off/8) & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STR Xd, [Xn, #imm12*8]  (64-bit store)
static inline uint32_t A_STR_X(int rd, int rn, int byte_off) {
    return 0xF9000000u | (((uint32_t)(byte_off/8) & 0xFFF) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

// STP X29, X30, [SP, #-16]!  (push frame)
static inline uint32_t A_STP_PUSH(void) {
    return 0xA9BF7BFDu;
}

// LDP X29, X30, [SP], #16  (pop frame)
static inline uint32_t A_LDP_POP(void) {
    return 0xA8C17BFDu;
}

// BL #offset  (branch-and-link, PC-relative, offset in instructions, ±128MB)
static inline uint32_t A_BL(int32_t insn_offset) {
    return 0x94000000u | ((uint32_t)insn_offset & 0x03FFFFFFu);
}

// B #offset  (unconditional branch)
static inline uint32_t A_B(int32_t insn_offset) {
    return 0x14000000u | ((uint32_t)insn_offset & 0x03FFFFFFu);
}

// BLR Xn  (branch-and-link to register)
static inline uint32_t A_BLR(int rn) {
    return 0xD63F0000u | ((uint32_t)rn << 5);
}

// BR Xn  (branch to register, no link)
static inline uint32_t A_BR(int rn) {
    return 0xD61F0000u | ((uint32_t)rn << 5);
}

// RET  (return via x30)
static inline uint32_t A_RET(void) {
    return 0xD65F03C0u;
}

// NOP
static inline uint32_t A_NOP(void) {
    return 0xD503201Fu;
}

// CMP Xn, Xm  (SUBS XZR, Xn, Xm)
static inline uint32_t A_CMP_R(int rn, int rm) {
    return 0xEB00001Fu | ((uint32_t)rm << 16) | ((uint32_t)rn << 5);
}

// CBNZ Xn, #offset  (compare-and-branch if non-zero)
static inline uint32_t A_CBNZ(int rn, int32_t insn_off) {
    return 0xB5000000u | (((uint32_t)insn_off & 0x7FFFFu) << 5) | (uint32_t)rn;
}

// CBZ Xn, #offset
static inline uint32_t A_CBZ(int rn, int32_t insn_off) {
    return 0xB4000000u | (((uint32_t)insn_off & 0x7FFFFu) << 5) | (uint32_t)rn;
}

// B.cond #offset  (ARM64 condition codes below)
static inline uint32_t A_BCOND(uint8_t cond, int32_t insn_off) {
    return 0x54000000u | (((uint32_t)insn_off & 0x7FFFFu) << 5) | (uint32_t)cond;
}

// ARM64 condition codes
#define A_EQ  0x0   // Equal                  (Z=1)
#define A_NE  0x1   // Not equal              (Z=0)
#define A_CS  0x2   // Carry set / unsigned >= (C=1)
#define A_CC  0x3   // Carry clear / unsigned < (C=0)
#define A_MI  0x4   // Minus / negative       (N=1)
#define A_PL  0x5   // Plus / positive        (N=0)
#define A_VS  0x6   // Overflow               (V=1)
#define A_VC  0x7   // No overflow            (V=0)
#define A_HI  0x8   // Unsigned higher        (C=1 && Z=0)
#define A_LS  0x9   // Unsigned lower/same    (C=0 || Z=1)
#define A_GE  0xA   // Signed >=              (N==V)
#define A_LT  0xB   // Signed <               (N!=V)
#define A_GT  0xC   // Signed >               (Z=0 && N==V)
#define A_LE  0xD   // Signed <=              (Z=1 || N!=V)
#define A_AL  0xE   // Always

// x86 condition code → ARM64 condition mapping (after SUBS / ADDS sets NZCV)
// x86 Jcc opcodes 0x70-0x7F (short) / 0x0F 0x80-0x8F (near):
//   JO=0 JNO=1 JB/JC=2 JAE/JNC=3 JE/JZ=4 JNE/JNZ=5
//   JBE=6 JA=7 JS=8 JNS=9 JP=10 JNP=11 JL=12 JGE=13 JLE=14 JG=15
static const uint8_t x86cc_to_arm64[16] = {
    A_VS, A_VC,  // JO, JNO
    A_CC, A_CS,  // JB, JAE   (note: x86 CF=ARM64 ~C, so CC↔JB, CS↔JAE)
    A_EQ, A_NE,  // JE, JNE
    A_LS, A_HI,  // JBE, JA
    A_MI, A_PL,  // JS, JNS
    A_AL, A_AL,  // JP, JNP  (no parity on ARM64 — fallback to interpreter)
    A_LT, A_GE,  // JL, JGE
    A_LE, A_GT,  // JLE, JG
};

// ---------------------------------------------------------------------------
// Block prologue / epilogue helpers
// ---------------------------------------------------------------------------

// Prologue: save frame, load all x86 registers from cpu_state into ARM64 regs
static inline void emit_prologue(arm64_buf_t *b) {
    arm64_emit(b, A_STP_PUSH());                        // save FP+LR
    // Load x86 regs from cpu->regs[] into dedicated ARM64 regs
    for (int i = 0; i < 8; i++) {
        arm64_emit(b, A_LDR_W(x86reg_to_arm64[i], AR_CPU, cpu_reg_offset(i)));
    }
}

// Epilogue: store all x86 registers back to cpu_state, restore frame, RET
static inline void emit_epilogue(arm64_buf_t *b) {
    for (int i = 0; i < 8; i++) {
        arm64_emit(b, A_STR_W(x86reg_to_arm64[i], AR_CPU, cpu_reg_offset(i)));
    }
    arm64_emit(b, A_LDP_POP());
    arm64_emit(b, A_RET());
}

// Store a new x86 EIP value into cpu->eip
static inline void emit_set_eip(arm64_buf_t *b, uint32_t eip) {
    arm64_mov_imm32(b, AR_T0, eip);
    arm64_emit(b, A_STR_W(AR_T0, AR_CPU,
                           (int)__builtin_offsetof(struct cpu_state, eip)));
}

// ---------------------------------------------------------------------------
// Top-level translator function (implemented in jit_arm64.c)
// ---------------------------------------------------------------------------

// Translate the x86 basic block at guest_eip into an arm64_buf_t.
// Returns true on success. tlb is used to read guest memory.
// The block ends at the first branch, call, ret, or after JIT_MAX_X86_INSNS.
bool jit_translate_block_arm64(uint32_t guest_eip, struct tlb *tlb,
                                struct cpu_state *cpu,
                                arm64_buf_t *out, uint32_t *end_eip);

#endif // EMU_JIT_ARM64_H
