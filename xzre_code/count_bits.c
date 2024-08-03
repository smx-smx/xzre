/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

u32 count_bits(u64 x){
	u32 result;
	for(result=0; x; ++result, x &= x-1);
	return result;
}
