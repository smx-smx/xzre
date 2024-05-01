/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

void *fake_lzma_alloc(void *opaque, size_t nmemb, size_t size){
	elf_info_t *elf_info = (elf_info_t *)opaque;
	EncodedStringId string_id = (EncodedStringId)size;
	return elf_symbol_get_addr(elf_info, string_id);
}
