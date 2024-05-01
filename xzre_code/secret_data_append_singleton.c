/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL secret_data_append_singleton(
	u8 *call_site, u8 *code,
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, unsigned operation_index
){
	if(global_ctx && !global_ctx->shift_operations[operation_index]){
		global_ctx->shift_operations[operation_index] = TRUE;
		void *func_start = NULL;
		if(!find_function(
			code, &func_start, NULL,
			global_ctx->lzma_code_start,
			global_ctx->lzma_code_end,
			FIND_NOP
		)){
			return FALSE;
		}

		if(!secret_data_append_from_code(
			func_start, global_ctx->lzma_code_end,
			shift_cursor, shift_count,
			call_site == NULL
		)){
			return FALSE;
		}

		global_ctx->num_shifted_bits += shift_count;
	}
	return TRUE;
}
