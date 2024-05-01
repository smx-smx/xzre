/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <elf.h>

void *elf_symbol_get_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id){
	Elf64_Sym *sym = elf_symbol_get(elf_info, encoded_string_id, 0);
	if(!sym){
		return NULL;
	}

	if(sym->st_value && sym->st_shndx){
		return (void *)PTRADD(elf_info->elfbase, sym->st_value);
	} else {
		return NULL;
	}
}
