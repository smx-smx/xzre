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

int main(int argc, char *argv[]){
	puts("xzre 0.1 by Smx :)");
	dasm_ctx_t ctx = {0};
	u8 *start = (u8 *)&dasm_sample;
	for(int i=0;; start += ctx.instruction_size, i++){
		int res = x86_dasm(&ctx, start, (u8 *)&dasm_sample_end);
		if(!res) break;
		//hexdump(&ctx, sizeof(ctx));
		printf(
			"[%2d]: opcode: 0x%08x (orig:0x%08X)  (l: %2ld) -- "
			"modrm: 0x%02x, reg:%d, operand: %lx, mem_disp: %lx\n", i,
			XZDASM_OPC(ctx.opcode), ctx.opcode,
			ctx.instruction_size, ctx.modrm,
			ctx.reg, ctx.operand,
			ctx.mem_disp);
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
	return 0;
}