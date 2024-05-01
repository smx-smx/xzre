/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL secret_data_append_item(
	secret_data_shift_cursor_t shift_cursor,
	unsigned operation_index,
	unsigned shift_count,
	int index, u8 *code
){
	return index && secret_data_append_singleton(
		code, code,
		shift_cursor, shift_count,
		operation_index
	);
}
