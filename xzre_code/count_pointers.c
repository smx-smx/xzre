/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL count_pointers(
	void **ptrs,
	u64 *count_out, 
	libc_imports_t *funcs
){
	if(!ptrs) return FALSE;
	if(!funcs) return FALSE;
	if(!funcs->malloc_usable_size) return FALSE;
	size_t blockSize = funcs->malloc_usable_size(ptrs);
	if(blockSize - 8 > 127) return FALSE;
	size_t nWords = blockSize >> 3;
	
	size_t i;
	for(i=0; i < nWords && ptrs[i]; ++i);
	*count_out = i;
	return TRUE;
}