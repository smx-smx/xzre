/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <stdio.h>
#include <unistd.h>

extern int x86_dasm(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

extern void dasm_sample(void);
extern void dasm_sample_end();

int main(int argc, char *argv[]){
	puts("xzre 0.1 by Smx :)");
	dasm_ctx_t ctx = {0};
	u8 *start = (u8 *)&dasm_sample;
	for(int i=0;; start += ctx.instruction_size, i++){
		int res = x86_dasm(&ctx, start, (u8 *)&dasm_sample_end);
		if(!res) break;
		//hexdump(&ctx, sizeof(ctx));
		printf(
			"[%2d]: opcode: 0x%08x  (l: %2ld) -- "
			"modrm: 0x%02x, reg:%d\n", i,
			XZDASM_OPC(ctx.opcode), ctx.instruction_size, ctx.modrm,
			ctx.reg);
	};

	return 0;
}