/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

u8 *find_string_reference(
	u8 *code_start,
	u8 *code_end,
	const char *str
){
	dasm_ctx_t dctx = {0};
	if(find_lea_instruction_with_mem_operand(code_start, code_end, &dctx, (void *)str)){
		return dctx.instruction;
	}
	return NULL;
}
