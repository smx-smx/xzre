/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL find_call_instruction(u8 *code_start, u8 *code_end, u8 *call_target, dasm_ctx_t *dctx){
	if(!secret_data_append_from_address(NULL, (secret_data_shift_cursor_t){ 0x81 }, 4, 7)){
		return FALSE;
	}
	dasm_ctx_t ctx = {0};
	if(!dctx){
		dctx = &ctx;
	}

	while(code_start < code_end){
		if(x86_dasm(dctx, code_start, code_end)){
			if(XZDASM_OPC(dctx->opcode) == X86_OPCODE_CALL
				&& (!call_target || &dctx->instruction[dctx->operand + dctx->instruction_size] == call_target)
			){
				return TRUE;
			}
			code_start += dctx->instruction_size;
		} else {
			code_start += 1;
		}
	}
	return FALSE;
}

