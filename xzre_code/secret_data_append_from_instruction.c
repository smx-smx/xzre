/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx, secret_data_shift_cursor_t *cursor){
	if(cursor->index <= 0x1C7
	&& XZDASM_OPC(dctx->opcode) != X86_OPCODE_MOV
	&& XZDASM_OPC(dctx->opcode) != X86_OPCODE_CMP
	&& !XZDASM_TEST_MASK(0x410100000101, 3, dctx->opcode)
	){
		global_ctx->secret_data[cursor->byte_index] |= 1 << (cursor->bit_index);
	}
	++cursor->index;
	return TRUE;
}
