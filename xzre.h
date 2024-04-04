/**
 * @file xzre.h
 * @author Stefano Moioli (smxdev4@gmail.com)
 * @brief XZ backdoor structures and functions
 * 
 */
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

#define CONCAT(x, y) x ## y
#define EXPAND(x, y) CONCAT(x, y)
#define PADDING(size) u8 EXPAND(_unknown, __LINE__)[size]

typedef struct __attribute__((packed)) {
	u8* first_instruction;
	u64 instruction_size;
	u8 flags;
	u8 flags2;
	PADDING(2);
	u8 lock_byte;
	u8 _unk1;
	u8 last_prefix;
	PADDING(4);
	u8 rex_byte;
	u8 modrm;
	u8 modrm_mod;
	u8 modrm_reg;
	u8 modrm_rm;
	PADDING(4);
	u8 byte_24;
	PADDING(3);
	u32 opcode;
	PADDING(4);
	u64 mem_disp;
	// e.g. in CALL
	u64 operand;
	PADDING(16);
	u8 insn_offset;
	PADDING(47);
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
	/**
	 * @brief pointed to the ELF base address in memory
	 */
	Elf64_Ehdr *elfbase;
	/**
	 * @brief virtual address of the first program header
	 */
	u64 first_vaddr;
	/**
	 * @brief pointer to the ELF program headers array in memory
	 */
	Elf64_Phdr *phdrs;
	/**
	 * @brief copy of the ELF program header count from the ELF header
	 */
	u64 e_phnum;
	/**
	 * @brief pointer to the ELF dynamic segment
	 */
	Elf64_Dyn *dyn;
	/**
	 * @brief number of entries in the ELF dynamic segment
	 */
	u64 dyn_num_entries;
	/**
	 * @brief pointer to the ELF string table
	 */
	char *strtab;
	/**
	 * @brief pointer to the ELF symbol table
	 */
	Elf64_Sym *symtab;
	/**
	 * @brief pointer to the ELF PLT relocations table
	 */
	Elf64_Rela *plt_relocs;
	/**
	 * @brief number of entries in the PLT relocation table
	 */
	u32 plt_relocs_num;
	/**
	 * @brief whether the loaded ELF contains PT_GNU_RELRO or not
	 * which specifies the location and size of a segment which
	 * may be made read-only after relocations have been processed.
	 */
	BOOL gnurelro_found;
	/**
	 * @brief location of the GNU relro segment
	 */
	u64 gnurelro_vaddr;
	/**
	 * @brief size of the GNU relro segment
	 */
	u64 gnurelro_memsize;
	/**
	 * @brief pointer to the EFL symbol versioning  (from DT_VERDEF)
	 */
	Elf64_Verdef *verdef;
	/**
	 * @brief number of entries in the symbol versioning table
	 */
	u64 verdef_num;
	Elf64_Versym *versym;
	Elf64_Rela *rela_relocs;
	u32 rela_relocs_num;
	u32 _unused0;
	Elf64_Relr *relr_relocs;
	u32 relr_relocs_num;
	PADDING(4);
	/**
	 * @brief
	 * page-aligned virtual address of the first executable ELF segment
	 */
	u64 code_segment_start;
	/**
	 * @brief 
	 * page-aligned virtual size of the first executable ELF segment
	 */
	u64 code_segment_size;
	PADDING(0x28);
	u8 flags;
	PADDING(7);
	/**
	 * @brief number of GNU hash buckets (from DT_GNU_HASH)
	 */
	u32 gnu_hash_nbuckets;
	/**
	 * @brief last valid bloom value
	 */
	u32 gnu_hash_last_bloom;
	u32 gnu_hash_bloom_shift;
	PADDING(4);
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
assert_offset(elf_info_t, code_segment_start, 0x98);
assert_offset(elf_info_t, code_segment_size, 0xA0);
assert_offset(elf_info_t, flags, 0xD0);
assert_offset(elf_info_t, gnu_hash_nbuckets, 0xd8);
assert_offset(elf_info_t, gnu_hash_last_bloom, 0xdc);
assert_offset(elf_info_t, gnu_hash_bloom_shift, 0xe0);
assert_offset(elf_info_t, gnu_hash_bloom, 0xe8);
assert_offset(elf_info_t, gnu_hash_buckets, 0xf0);
assert_offset(elf_info_t, gnu_hash_chain, 0xf8);

typedef struct __attribute__((packed)) {
	u32 resolved_imports_count;
	PADDING(12);
	uid_t (*getuid)(void);
	void (*exit)(int status);
	int (*setresgid)(gid_t rgid, gid_t egid, gid_t sgid); 
	int (*setresuid)(uid_t ruid, uid_t euid, uid_t suid);
	int (*system)(const char *command);
	ssize_t (*write)(int fd, const void *buf, size_t count);
	int (*pselect)(
		int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct timespec *timeout,
		const sigset_t *sigmask);
	PADDING(0x10);
	int (*setlogmask)(int mask);
	int (*shutdown)(int sockfd, int how);
} system_imports_t;

assert_offset(system_imports_t, resolved_imports_count, 0);
assert_offset(system_imports_t, getuid, 0x10);
assert_offset(system_imports_t, exit, 0x18);
assert_offset(system_imports_t, setresgid, 0x20);
assert_offset(system_imports_t, setresuid, 0x28);
assert_offset(system_imports_t, system, 0x30);
assert_offset(system_imports_t, write, 0x38);
assert_offset(system_imports_t, pselect, 0x40);
assert_offset(system_imports_t, setlogmask, 0x58);
assert_offset(system_imports_t, shutdown, 0x60);

typedef struct __attribute__((packed)) {
	int (*RSA_public_decrypt)(
		int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	PADDING(0x58);
	void (*RSA_get0_key)(
		const RSA *r,
		const BIGNUM **n,
		const BIGNUM **e,
		const BIGNUM **d);
	int (*BN_num_bits)(const BIGNUM *a);
	EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(
		int type, ENGINE *e,
		const unsigned char *key, size_t keylen);
	EVP_MD_CTX *(*EVP_MD_CTX_new)(void);
	int (*EVP_DigestVerifyInit)(
		EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
	PADDING(0x8);
	void (*EVP_MD_CTX_free)(EVP_MD_CTX *ctx);
	void (*EVP_PKEY_free)(EVP_PKEY *key);
	EVP_CIPHER_CTX *(*EVP_CIPHER_CTX_new)(void);
	int (*EVP_DecryptInit_ex)(
		EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
		ENGINE *impl, const unsigned char *key, const unsigned char *iv);
	int (*EVP_DecryptUpdate)(
		EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, const unsigned char *in, int inl);
	PADDING(8);
	void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *ctx);
	EVP_CIPHER *(*EVP_chacha20)(void);
	RSA *(*RSA_new)(void);
	BIGNUM *(*BN_dup)(const BIGNUM *from);
	BIGNUM (*BN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret);
	PADDING(16);
	int (*RSA_sign)(
		int type,
		const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, RSA *rsa);
	int (*BN_bn2bin)(const BIGNUM *a, unsigned char *to);
	void (*RSA_free)(RSA *rsa);
	void (*BN_free)(BIGNUM *a);
	system_imports_t *system;
	u32 resolved_imports_count;
} imported_funcs_t;

assert_offset(imported_funcs_t, RSA_public_decrypt, 0);
assert_offset(imported_funcs_t, RSA_get0_key, 0x60);
assert_offset(imported_funcs_t, BN_num_bits, 0x68);
assert_offset(imported_funcs_t, EVP_PKEY_new_raw_public_key, 0x70);
assert_offset(imported_funcs_t, EVP_MD_CTX_new, 0x78);
assert_offset(imported_funcs_t, EVP_DigestVerifyInit, 0x80);
assert_offset(imported_funcs_t, EVP_MD_CTX_free, 0x90);
assert_offset(imported_funcs_t, EVP_PKEY_free, 0x98);
assert_offset(imported_funcs_t, EVP_CIPHER_CTX_new, 0xA0);
assert_offset(imported_funcs_t, EVP_DecryptInit_ex, 0xA8);
assert_offset(imported_funcs_t, EVP_DecryptUpdate, 0xB0);
assert_offset(imported_funcs_t, EVP_CIPHER_CTX_free, 0xC0);
assert_offset(imported_funcs_t, EVP_chacha20, 0xC8);
assert_offset(imported_funcs_t, RSA_new, 0xD0);
assert_offset(imported_funcs_t, BN_dup, 0xD8);
assert_offset(imported_funcs_t, BN_bin2bn, 0xE0);
assert_offset(imported_funcs_t, RSA_sign, 0xF8);
assert_offset(imported_funcs_t, BN_bn2bin, 0x100);
assert_offset(imported_funcs_t, RSA_free, 0x108);
assert_offset(imported_funcs_t, BN_free, 0x110);
assert_offset(imported_funcs_t, system, 0x118);
assert_offset(imported_funcs_t, resolved_imports_count, 0x120);

typedef struct __attribute__((packed)) {
	PADDING(8);
	/**
	 * @brief 
	 * pointer to the structure containing resolved OpenSSL and system functions
	 */
	imported_funcs_t *imported_funcs;
	PADDING(0x70);
	/**
	 * @brief 
	 * the shifter will use this address as the minimum search address
	 * any instruction below this address will be rejected
	 */
	u64 code_range_start;
	/**
	 * @brief 
	 * the shifter will use this address as the maximum search address
	 * any instruction beyond this address will be rejected
	 */
	u64 code_range_end;
	PADDING(0x78);
	/**
	 * @brief 
	 * holds the secret data used for the chacha key generation
	 */
	u8 secret_data[57];
	/**
	 * @brief
	 * holds the shift operation states
	 * written by @ref secret_data_append_singleton
	 */
	u8 shift_operations[31];
	/**
	 * @brief 
	 * cumulative number of reg2reg instructions 
	 * successfully validated by the data shifter
	 */
	u32 reg2reg_instructions_count;
} global_context_t;

assert_offset(global_context_t, imported_funcs, 8);
assert_offset(global_context_t, code_range_start, 0x80);
assert_offset(global_context_t, code_range_end, 0x88);
assert_offset(global_context_t, secret_data, 0x108);
assert_offset(global_context_t, shift_operations, 0x141);
assert_offset(global_context_t, reg2reg_instructions_count, 0x160);

/**
 * @brief represents a shift register, which will shift 
 * a '1' into the secret data array.
 * the low 3 bits represent the bit index, while the rest represents the byte index
 * this is convenient, since a simple increment will increment the buffer position correctly
 */
typedef union {
	struct {
		/** bit index in the current byte indicated by @ref byte_index */
		u32 bit_index : 3;
		/** byte index into the secret data array */
		u32 byte_index : 29;
	};
	/** the initial value */
	u32 index;
} secret_data_shift_cursor;

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
 * @brief finds a reg2reg instruction
 *
 * a reg2reg instruction is an x64 instruction with one of the following characteristics:
 * - a primary opcode of 0x89 (MOV/JNS)
 * or, alternatively, passing the following filter:
 * - ((0x505050500000505uLL >> (((dctx->opcode) & 0xFF) + 0x7F)) & 1) != 0
 * NOTE: the opcode in 'dctx->opcode' is the actual opcode +0x80 
 * TODO: inspect x64 manual to find the exact filter
 *
 * the instruction must also satisfy the following conditions:
 * - NOT have REX.B and REX.R set (no extension bits)
 * - MODRM.mod must be 3 (register-direct addressing mode)
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param dctx disassembler context to hold the state
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_reg2reg_instruction(u8 *code_start, u8 *code_end, dasm_ctx_t *dctx);

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
 * @brief locates the function prologue.
 * it will try to backtrack and synchronize the code stream, calling @ref find_function_prologue
 * for each iteration
 * 
 * @param code_start address to start searching from
 * @param func_start_0 if provided, will be filled with the address of the first candidate match, obtained by starting the search at @p code_start + 0
 * @param func_start_1 if provided, will be filled with the address of the second candidate match, obtained by starting the search at @p code_start + 1
 * @param search_base lowest address, where backtracking is stopped
 * @param code_end address to stop searching at
 * @param find_mode 
 * @return BOOL 
 */
extern BOOL find_function_prologue_ex(
	u8 *code_start,
	u8 *func_start_0,
	u8 *func_start_1,
	u8 *search_base,
	u8 *code_end,
	FuncFindType find_mode);

/**
 * @brief checks if given ELF file contains an elf segment with the given parameters
 * 
 * @param elf_info elf context
 * @param vaddr the starting virtual address of the segment
 * @param size the size of the segment
 * @param p_flags the segment protection flags (PF_*)
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL elf_contains_segment(elf_info_t *elf_info, u64 vaddr, u64 size, u32 p_flags);

/**
 * @brief Parses the given in-memory ELF file into elf_info
 * 
 * @param ehdr pointer to the beginning of the ELF header
 * @param elf_info pointer to the structure that will hold the parsed information
 * @return BOOL TRUE if parsing completed successfully, FALSE otherwise
 */
extern BOOL elf_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

/**
 * @brief Looks up an ELF symbol from a parsed ELF
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id string ID of the symbol name
 * @param sym_version optional string representing the symbol version (e.g. "GLIBC_2.2.5")
 * @return Elf64_Sym* pointer to the ELF symbol, or NULL if not found
 */
extern Elf64_Sym *elf_symbol_get(elf_info_t *elf_info, u32 encoded_string_id, const char *sym_version);

/**
 * @brief Looks up an ELF symbol from a parsed ELF, and returns its memory address
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id string ID of the symbol name
 * @return void* the address of the symbol
 */
extern void *elf_symbol_get_addr(elf_info_t *elf_info, u32 encoded_string_id);

/**
 * @brief Obtains the size of the first executable page in the given ELF file
 * 
 * @param elf_info the parsed ELF context, which will be updated with the address and size of the code segment
 * @param pSize variable that will hold the page-aligned segment size
 * @return BOOL TRUE on success, FALSE if the executable segment wasn't found
 */
extern BOOL elf_get_code_size(elf_info_t *elf_info, u64 *pSize);

/**
 * @brief gets the fake LZMA allocator, used for imports resolution
 * 
 * @return lzma_allocator* 
 */
extern lzma_allocator *get_lzma_allocator();

/**
 * @brief Calls @ref secret_data_append_singleton, if @p flags are non-zero
 *
 * @param shift_cursor the initial shift index
 * @param operation_index identification for this shift operation
 * @param reg2reg_instruction_count number of"reg2reg" instructions expected in the function pointed to by @p code
 * @param flags must be non-zero in order for the operation to be executed
 * @param code pointer to code that will be checked by the function, to "authorize" the data load
 * @return BOOL TRUE if validation was successful and data was added, FALSE otherwise
 */
extern BOOL secret_data_append_if_flags(
	secret_data_shift_cursor shift_cursor,
	unsigned operation_index,
	unsigned reg2reg_instruction_count,
	int flags, u8 *code);

/**
 * @brief Shifts data in the secret data store, after validation of @p code.
 * this function is intended to be invoked only once for each @p operation_index value.
 * @p operation_index will be used as an index into a global array of flags,
 * so that multiple calls with the same value will be a NO-OP.
 * 
 * the @p code will be verified to check if the shift operation should be allowed or not.
 * the algorithm will:
 * - locate the beginning of the function, by scanning for the `endbr64` instruction
 *    and making sure that the code lies between a pre-defined code range (TODO: figure out where the range is set)
 * - search for @p reg2reg_instruction_count number of "reg2reg" functions (explained below)
 * - for each instruction, shift a '1' in the data register, and increment the shift cursor to the next bit index
 * if, at any given point, a non reg2reg instruction is encountered, the whole loop will stop.
 *
 * a reg2reg instruction is an x64 instruction with one of the following characteristics:
 * - primary opcode of 0x89 (MOV) or 0x3B (CMP)
 * or, alternatively, an opcode that passes the following validation
 *  opcode_check = opcode - 0x83;
 *  if ( opcode_check > 0x2E || ((0x410100000101 >> opcode_value) & 1) == 0 )
 *
 * additionally, checks outlined in @ref find_reg2reg_instruction must also pass
 * NOTE: the opcode in 'opcode' is the actual opcode +0x80 
 * TODO: inspect x64 manual to find the exact filter
 *
 * if @p call_site is supplied, a preliminary check will be conducted to see if the caller function
 * contains a CALL-relative instruction.
 * several functions have a CALL in the prologue which serves a dual purpose:
 * - push more data in the secret data store
 * - check if the call is authorized (the code is in the authorized range, and starts with a CALL-relative instruction)
 *
 *
 * @param call_site if supplied, it will be checked if it contains a valid CALL-relative instruction
 * @param code pointer to code that will be checked by the function, to "authorize" the data load
 * @param shift_cursor the initial shift index
 * @param reg2reg_instruction_count number of"reg2reg" instructions expected in the function pointed to by @p code
 * @param operation_index index/id of shit shift operation
 * @return BOOL 
 */
extern BOOL secret_data_append_singleton(
	u8 *call_site, u8 *code,
	secret_data_shift_cursor shift_cursor,
	unsigned reg2reg_instruction_count, unsigned operation_index);

#include "util.h"
#endif