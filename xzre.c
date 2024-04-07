/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern void dasm_sample(void);
extern void dasm_sample_end();
extern void dasm_sample_dummy_location();
extern BOOL secret_data_append_trampoline(secret_data_shift_cursor shift_cursor, unsigned shift_count);

static global_context_t my_global_ctx = { 0 };

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
	global_ctx->code_range_start = (u64)&__executable_start;
	global_ctx->code_range_end = (u64)&__etext;
}

void xzre_secret_data_test(){
	// disable x86_dasm shift slot
	my_global_ctx.shift_operations[2] = 1;

	secret_data_shift_cursor cursor = {
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


/**
 * @brief quick and dirty hack to get the ldso ELF location
 * 
 * @return void* 
 */
static void *get_ldso_elf(){
	char cmdBuf[128];
	char getLdElf[] = "grep -E 'r--p 00000000.*/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2' /proc/%zu/maps | cut -d '-' -f1";
	snprintf(cmdBuf, sizeof(cmdBuf), getLdElf, getpid());
	FILE *hProc = popen(cmdBuf, "r");
	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	char *s = fgets(cmdBuf, sizeof(cmdBuf), hProc);
	pclose(hProc);
	if(!s) return NULL;
	u64 addr = strtoull(s, NULL, 16);
	return (void *)addr;
}

/**
 * @brief quick and dirty hack to get the main ELF location
 * 
 * @return void* 
 */
static void *get_main_elf(){
	char cmdBuf[128];
	char getLdElf[] = "grep -E 'r--p 00000000.*/usr/sbin/sshd' /proc/%zu/maps | cut -d '-' -f1";
	snprintf(cmdBuf, sizeof(cmdBuf), getLdElf, getpid());
	FILE *hProc = popen(cmdBuf, "r");
	memset(cmdBuf, 0x00, sizeof(cmdBuf));
	char *s = fgets(cmdBuf, sizeof(cmdBuf), hProc);
	pclose(hProc);
	if(!s) return NULL;
	u64 addr = strtoull(s, NULL, 16);
	return (void *)addr;
}

extern void *got_ref;

//#define DUMP_STR_CODE_BLOCKS

void main_shared(){
	// prevent fork bomb in system command
	unsetenv("LD_PRELOAD");
	xzre_secret_data_bypass();
	
	void *ldso_elf = get_main_elf();
	if(!ldso_elf){
		puts("Failed to get main elf");
		exit(1);
	}

	elf_handles_t handles = {0};
	elf_info_t einfo;
	if(!elf_parse(ldso_elf, &einfo)){
		puts("elf_parse failed");
		return;
	}

#ifdef DUMP_STR_CODE_BLOCKS
	mkdir("/tmp/dumps", (mode_t)0755);
#endif

	/** populate the string references table, and dump it */
	string_references_t strings = { 0 };
	elf_find_string_references(&einfo, &strings);
	for(int i=0; i<ARRAY_SIZE(strings.entries); i++){
		string_item_t *item = &strings.entries[i];
		printf("str %2d: id=0x%x, start=%p, end=%p, xref=%p (size: 0x%04lx, xref_offset: 0x%04lx)\n",
			i, item->string_id, item->code_start, item->code_end, item->xref,
				(item->code_start && item->code_end) ? PTRDIFF(item->code_end, item->code_start) : 0,
				(item->code_start && item->xref) ? PTRDIFF(item->xref, item->code_start) : 0);

		if(!item->code_start || !item->code_end){
			continue;
		}

	#ifdef DUMP_STR_CODE_BLOCKS
		/** dump the code block that was identified by the malware */
		char dumpName[64];
		snprintf(dumpName, sizeof(dumpName), "/tmp/dumps/str_%x.bin", item->string_id);
		FILE *dump = fopen(dumpName, "wb");
		fwrite(item->code_start, sizeof(u8), PTRDIFF(item->code_end, item->code_start), dump);
		fclose(dump);
	#endif
	}

	puts("main_shared(): OK");
}


int main(int argc, char *argv[]){
	puts("xzre 0.1 by Smx :)");
	dasm_ctx_t ctx = {0};
	u8 *start = (u8 *)&dasm_sample;
	for(int i=0;; start += ctx.instruction_size, i++){
		int res = x86_dasm(&ctx, start, (u8 *)&dasm_sample_end);
		if(!res) break;
		//hexdump(&ctx, sizeof(ctx));
		printf(
			"[%2d]: opcode: 0x%08x (orig:0x%08X)  (l: %2llu) -- "
			"modrm: 0x%02x (%d, %d, %d), operand: %lx, mem_disp: %lx, rex.br: %d, f: %02hhx\n", i,
			XZDASM_OPC(ctx.opcode), ctx.opcode,
			ctx.instruction_size,
			ctx.modrm, ctx.modrm_mod, ctx.modrm_reg, ctx.modrm_rm,
			ctx.operand,
			ctx.mem_disp,
			// 1: has rex.br, 0 otherwise
			(ctx.rex_byte & 5) != 0,
			ctx.flags);
		printf("      --> ");
		for(int i=0; i<ctx.instruction_size; i++){
			printf("%02hhx ", ctx.instruction[i]);
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