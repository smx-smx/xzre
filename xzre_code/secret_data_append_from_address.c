/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL secret_data_append_from_address(
	void *addr,
	secret_data_shift_cursor_t shift_cursor,
	unsigned shift_count, unsigned operation_index
){
	u8 *code = (u8 *)addr;
	if((uintptr_t)addr <= 1){
		code = (u8 *)__builtin_return_address(0);
	}
	return secret_data_append_singleton(
		addr, code,
		shift_cursor, shift_count,
		operation_index
	);
}
