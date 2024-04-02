/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#ifndef __XZRE_H
#define __XZRE_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uptr;

#define UPTR(x) ((uptr)(x))
#define PTRADD(a, b) (UPTR(a) + UPTR(b))
#define PTRDIFF(a, b) (UPTR(a) - UPTR(b))

// opcode is always +0x80 for the sake of it (yet another obfuscation)
#define XZDASM_OPC(op) (op - 0x80)

enum DasmFlags {
	// has lock prefix
	DF_LOCK = 1,
	// has address size override
	DF_ASIZE = 8,
	// has rex
	DF_REX = 0x20
};

#define assert_offset(t, f, o) static_assert(offsetof(t, f) == o)

typedef struct __attribute((packed)) {
	u64 first_instruction;
	u64 instruction_size;
	u8 flags;
	u8 flags2;
	u8 _unk0[2]; // likely padding
	u8 lock_byte;
	u8 _unk1;
	u8 last_prefix;
	u8 _unk2[4];
	u8 rex_byte;
	u8 modrm;
	u8 byte_1c;
	u8 byte_1d;
	u8 reg;
	u8 _unk3[4];
	u8 byte_24;
	u8 _unk4[3];
	u32 opcode;
	u8 _unk5[4];
	u64 mem_offset;
	// e.g. in CALL
	u64 operand;
	u64 _unk6[2];
	u8 insn_offset;
	u8 _unk8[47];
} dasm_ctx_t;

assert_offset(dasm_ctx_t, first_instruction, 0);
assert_offset(dasm_ctx_t, instruction_size, 8);
assert_offset(dasm_ctx_t, flags, 0x10);
assert_offset(dasm_ctx_t, flags2, 0x11);
assert_offset(dasm_ctx_t, lock_byte, 0x14);
assert_offset(dasm_ctx_t, last_prefix, 0x16);
assert_offset(dasm_ctx_t, rex_byte, 0x1B);
assert_offset(dasm_ctx_t, modrm, 0x1C);
assert_offset(dasm_ctx_t, opcode, 0x28);
assert_offset(dasm_ctx_t, mem_offset, 0x30);
assert_offset(dasm_ctx_t, operand, 0x38);
assert_offset(dasm_ctx_t, insn_offset, 0x50);
static_assert(sizeof(dasm_ctx_t) == 128);

extern int x86_dasm(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

/**
 * @brief finds a call instruction
 *
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param call_target optional call target address. pass 0 to find any call
 * @param dctx empty disassembler context to hold the state
 * @return int TRUE if found, FALSE otherwise
 */
extern int find_call_instruction(uint8_t *code_start, uint8_t *code_end, uint8_t *call_target, dasm_ctx_t *dctx);

#include "util.h"
#endif