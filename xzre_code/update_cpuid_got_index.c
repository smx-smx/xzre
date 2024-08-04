/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

void update_cpuid_got_index(elf_entry_ctx_t *ctx){
	ctx->got_ctx.cpuid_fn = (void *)cpuid_reloc_consts.cpuid_got_index;
}
