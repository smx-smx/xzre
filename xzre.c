/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern void dasm_sample(void);
extern void dasm_sample_end();
extern void dasm_sample_dummy_location();
extern BOOL secret_data_append_trampoline(secret_data_shift_cursor shift_cursor, unsigned shift_count);

extern char __executable_start;
extern char __etext;

static global_context_t my_global_ctx = { 0 };

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