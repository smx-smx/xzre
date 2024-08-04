/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <elf.h>

BOOL resolve_libc_imports(
	struct link_map *libc,
	elf_info_t *libc_info,
	libc_imports_t *imports
){
	lzma_allocator *resolver = get_lzma_allocator();
	if(!elf_parse((Elf64_Ehdr *)libc->l_addr, libc_info)){
		return FALSE;
	}
	resolver->opaque = libc_info;
	imports->read = lzma_alloc(STR_read, resolver);
	if(imports->read)
		++imports->resolved_imports_count;
	imports->__errno_location = lzma_alloc(STR_errno_location, resolver);
	if(imports->__errno_location)
		++imports->resolved_imports_count;
	
	return imports->resolved_imports_count == 2;
}
