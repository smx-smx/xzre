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

#include <lzma.h>
#include <openssl/rsa.h>
#include <elf.h>

#define UPTR(x) ((uptr)(x))
#define PTRADD(a, b) (UPTR(a) + UPTR(b))
#define PTRDIFF(a, b) (UPTR(a) - UPTR(b))

// opcode is always +0x80 for the sake of it (yet another obfuscation)
#define XZDASM_OPC(op) (op - 0x80)

typedef int BOOL;

typedef enum {
	// has lock prefix
	DF_LOCK = 1,
	// has es-segment override
	DF_ESEG = 2,
	// has operand size override
	DF_OSIZE = 4,
	// has address size override
	DF_ASIZE = 8,
	// has rex
	DF_REX = 0x20
} DasmFlags;

typedef enum {
	// ELF has DT_VERSYM
	X_ELF_VERSYM = 0x10,
	// ELF has DF_1_NOW
	X_ELF_NOW = 0x20
} ElfFlags;

typedef enum {
	// register-indirect addressing or no displacement
	MRM_I_REG, // 00
	// indirect with one byte displacement
	MRM_I_DISP1, // 01
	// indirect with four byte displacement
	MRM_I_DISP4, // 10
	// direct-register addressing
	MRM_D_REG // 11
} ModRm_Mod;

typedef enum {
	// find function beginning by looking for endbr64
	FIND_ENDBR64,
	// find function beginning by looking for padding,
	// then getting the instruction after it
	FIND_NOP
} FuncFindType;

#define assert_offset(t, f, o) static_assert(offsetof(t, f) == o)

typedef struct __attribute__((packed)) {
	u8* first_instruction;
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
	u8 modrm_mod;
	u8 modrm_reg;
	u8 modrm_rm;
	u8 _unk3[4];
	u8 byte_24;
	u8 _unk4[3];
	u32 opcode;
	u8 _unk5[4];
	u64 mem_disp;
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
assert_offset(dasm_ctx_t, modrm_mod, 0x1D);
assert_offset(dasm_ctx_t, modrm_reg, 0x1E);
assert_offset(dasm_ctx_t, modrm_rm, 0x1F);
assert_offset(dasm_ctx_t, opcode, 0x28);
assert_offset(dasm_ctx_t, mem_disp, 0x30);
assert_offset(dasm_ctx_t, operand, 0x38);
assert_offset(dasm_ctx_t, insn_offset, 0x50);
static_assert(sizeof(dasm_ctx_t) == 128);

typedef struct __attribute__((packed)) {
	Elf64_Ehdr *elfbase;
	u64 first_vaddr;
	Elf64_Phdr *phdrs;
	u64 e_phnum;
	Elf64_Dyn *dyn;
	u64 dyn_num_entries;
	char *strtab;
	Elf64_Sym *symtab;
	Elf64_Rela *plt_relocs;
	u32 plt_relocs_num;
	BOOL gnurelro_found;
	u64 gnurelro_vaddr;
	u64 gnurelro_memsize;
	Elf64_Verdef *verdef;
	u64 verdef_num;
	Elf64_Versym *versym;
	Elf64_Rela *rela_relocs;
	u32 rela_relocs_num;
	u32 _unused0;
	Elf64_Relr *relr_relocs;
	u32 relr_relocs_num;
	u8 _unknown0[60];
	u8 flags;
	u8 _unknown1[7];
	u32 gnu_hash_nbuckets;
	u32 gnu_hash_last_bloom;
	u32 gnu_hash_bloom_shift;
	u8 _unused1[4];
	u64 *gnu_hash_bloom;
	u32 *gnu_hash_buckets;
	u32 *gnu_hash_chain;
} elf_info_t;

assert_offset(elf_info_t, elfbase, 0x0);
assert_offset(elf_info_t, first_vaddr, 0x8);
assert_offset(elf_info_t, phdrs, 0x10);
assert_offset(elf_info_t, e_phnum, 0x18);
assert_offset(elf_info_t, dyn, 0x20);
assert_offset(elf_info_t, dyn_num_entries, 0x28);
assert_offset(elf_info_t, strtab, 0x30);
assert_offset(elf_info_t, symtab, 0x38);
assert_offset(elf_info_t, plt_relocs, 0x40);
assert_offset(elf_info_t, plt_relocs_num, 0x48);
assert_offset(elf_info_t, gnurelro_found, 0x4C);
assert_offset(elf_info_t, gnurelro_vaddr, 0x50);
assert_offset(elf_info_t, gnurelro_memsize, 0x58);
assert_offset(elf_info_t, verdef, 0x60);
assert_offset(elf_info_t, verdef_num, 0x68);
assert_offset(elf_info_t, versym, 0x70);
assert_offset(elf_info_t, rela_relocs, 0x78);
assert_offset(elf_info_t, rela_relocs_num, 0x80);
assert_offset(elf_info_t, relr_relocs, 0x88);
assert_offset(elf_info_t, relr_relocs_num, 0x90);
assert_offset(elf_info_t, flags, 0xD0);
assert_offset(elf_info_t, gnu_hash_nbuckets, 0xd8);
assert_offset(elf_info_t, gnu_hash_last_bloom, 0xdc);
assert_offset(elf_info_t, gnu_hash_bloom_shift, 0xe0);
assert_offset(elf_info_t, gnu_hash_bloom, 0xe8);
assert_offset(elf_info_t, gnu_hash_buckets, 0xf0);
assert_offset(elf_info_t, gnu_hash_chain, 0xf8);

/**
 * @brief disassembles the given x64 code
 *
 * @param ctx empty disassembler context to hold the state
 * @param code_start pointer to the start of buffer (first disassemblable location)
 * @param code_end pointer to the end of the buffer
 * @return int TRUE if disassembly was successful, FALSE otherwise
 */
extern int x86_dasm(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

/**
 * @brief finds a call instruction
 *
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param call_target optional call target address. pass 0 to find any call
 * @param dctx empty disassembler context to hold the state
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_call_instruction(u8 *code_start, u8 *code_end, u8 *call_target, dasm_ctx_t *dctx);

/**
 * @brief finds a lea instruction
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param displacement the memory displacement operand of the target lea instruction
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_lea_instruction(u8 *code_start, u8 *code_end, u64 displacement);

/**
 * @brief locates the function prologue
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param output pointer to receive the resulting prologue address, if found
 * @param find_mode prologue search mode/strategy
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_function_prologue(u8 *code_start, u8 *code_end, u8 **output, FuncFindType find_mode);

/**
 * @brief checks if given ELF file contains an elf segment with the given parameters
 * 
 * @param elf_info elf context
 * @param vaddr the starting virtual address of the segment
 * @param size the size of the segment
 * @param p_flags the segment protection flags (PF_*)
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL elf_contains_segment(elf_info_t *elf_info, u64 vaddr, u64 size, u32 p_flags, int step);

/**
 * @brief Parses the given in-memory ELF file into elf_info
 * 
 * @param ehdr pointer to the beginning of the ELF header
 * @param elf_info pointer to the structure that will hold the parsed information
 * @return BOOL TRUE if parsing completed successfully, FALSE otherwise
 */
extern BOOL elf_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

/**
 * @brief gets the fake LZMA allocator, used for imports resolution
 * 
 * @return lzma_allocator* 
 */
extern lzma_allocator *get_lzma_allocator();

#include "util.h"
#endif