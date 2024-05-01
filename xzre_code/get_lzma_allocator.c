/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

lzma_allocator *get_lzma_allocator(void){
	return &get_lzma_allocator_address()->allocator;
}
