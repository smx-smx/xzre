/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL find_lea_instruction(u8 *code_start, u8 *code_end, u64 displacement){

	if(!secret_data_append_from_call_site(
		(secret_data_shift_cursor_t){ 0x7C }, 
		5, 6, 0)
	){
		return FALSE;
	}
	dasm_ctx_t dctx = {0};
	for(;code_start < code_end; ++code_start){
		if(x86_dasm(&dctx, code_start, code_end)
			&& XZDASM_OPC(dctx.opcode) == X86_OPCODE_LEA
			&& (dctx.flags2 & DF2_FLAGS_MEM) == DF2_MEM_DISP
			&& (dctx.mem_disp == displacement || dctx.mem_disp == -displacement)
		){
			return TRUE;
		}
	}
	return FALSE;
}