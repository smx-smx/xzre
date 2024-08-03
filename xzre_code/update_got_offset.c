/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

void update_got_offset(elf_entry_ctx_t *ctx){
	ctx->got_ctx.got_offset = cpuid_reloc_consts.cpuid_random_symbol_got_offset;
}
