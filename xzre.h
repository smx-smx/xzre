/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#ifndef __XZRE_H
#define __XZRE_H

#include <assert.h>
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

typedef struct {
	/* 0x0 */
	u64 first_instruction;
	/* 0x8 */
	u64 instruction_size;
	/* 0x10 */
	u8 flags;
	/* 0x18 */
	u8 flags2;
	u8 _unk0[2]; // likely padding
	u8 lock_byte;
	u8 _unk1;
	u8 last_prefix;
	u8 _unk2[4];
	u8 rex_byte;
	/* 0x1C */
	u8 modrm;
	u8 byte_1c;
	u8 byte_1d;
	u8 reg;
	u8 _unk3[4];
	u8 byte_24;
	u32 opcode;
	u8 _unk5[4];
	u64 mem_offset;
	u64 _unk7;
	u8 insn_offset;
	u8 _unk8[56];
} dasm_ctx_t;

static_assert(sizeof(dasm_ctx_t) == 128);

#include "util.h"
#endif