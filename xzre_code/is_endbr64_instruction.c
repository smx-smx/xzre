/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL is_endbr64_instruction(u8 *code_start, u8 *code_end, u32 low_mask_part){
	if((code_end - code_start) > 3){
		return *code_start + (low_mask_part | 0x5E20000) == 0xF223;
	}
	return FALSE;
}
