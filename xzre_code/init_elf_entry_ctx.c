/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

void init_elf_entry_ctx(elf_entry_ctx_t *ctx){
	ctx->symbol_ptr = (void *)&cpuid_random_symbol;
	ctx->got_ctx.return_address = (void *)ctx->frame_address[3];
	update_got_offset(ctx);
	get_cpuid_got_index(ctx);
	ctx->got_ctx.got_ptr = NULL;
}
