/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/

#include "xzre.h"
#include <elf.h>
#include <openssl/bn.h>

#ifndef DT_RELRSZ
#define DT_RELRSZ 35 /* Total size of RELR relative relocations */
#endif

#ifndef DT_RELR
#define DT_RELR	36 /* Address of RELR relative relocations */
#endif

BOOL elf_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info){
	if(!ehdr || !elf_info){
		return FALSE;
	}

	memset(elf_info, 0x00, sizeof(*elf_info));
	elf_info->elfbase = ehdr;
	elf_info->phdrs = (Elf64_Phdr *)PTRADD(ehdr, ehdr->e_phoff);
	int i; Elf64_Phdr *phdr;
	u64 first_vaddr = -1;
	int dynamic_idx = -1;
	for(i=0, phdr = elf_info->phdrs; i<ehdr->e_phnum; i++, phdr++){
		if(phdr->p_type == PT_LOAD){
			if(phdr->p_vaddr < first_vaddr){
				first_vaddr = phdr->p_vaddr;
			}
		} else if(phdr->p_type == PT_DYNAMIC){
			dynamic_idx = i;
		} else if(is_gnu_relro(phdr->p_type, 0xA0000000)){
			if(elf_info->gnurelro_found){
				return FALSE;
			}
			elf_info->gnurelro_vaddr = phdr->p_vaddr;
			elf_info->gnurelro_found = TRUE;
			elf_info->gnurelro_memsize = phdr->p_memsz;
		}
	}
	if(first_vaddr == -1 || dynamic_idx == -1){
		return FALSE;
	}
	elf_info->first_vaddr = first_vaddr;
	
	Elf64_Phdr *dyn_phdr = &elf_info->phdrs[dynamic_idx];
	Elf64_Dyn *dyn = (Elf64_Dyn *)PTRADD(ehdr, PTRDIFF(dyn_phdr->p_vaddr, first_vaddr));
	elf_info->dyn = dyn;
	elf_info->dyn_num_entries = dyn_phdr->p_memsz / sizeof(Elf64_Dyn);
	if(!elf_contains_vaddr(elf_info, dyn, dyn_phdr->p_memsz, PF_R)){
		return FALSE;
	}

	gnu_hash_table_t *gnu_hash = NULL;

	u64 d_pltrelsz = -1;
	u64 d_relasz = -1;
	u64 d_relrsz = -1;
	BOOL have_verdef_num = FALSE;

	for(i=0; i<elf_info->dyn_num_entries; i++, dyn++){
		if(dyn->d_tag == DT_NULL){
			elf_info->dyn_num_entries = i;
			break;
		}
		switch(dyn->d_tag){
			case DT_JMPREL:
				elf_info->plt_relocs = (Elf64_Rela *)dyn->d_un.d_ptr;
				break;
			case DT_BIND_NOW:
				elf_info->flags |= X_ELF_NOW;
				break;
			case DT_FLAGS:
				if((dyn->d_un.d_val & DF_BIND_NOW) != 0){
					elf_info->flags |= X_ELF_NOW;
				}
				break;
			case DT_RELRSZ:
				d_relrsz = dyn->d_un.d_val;
				break;
			case DT_RELR:
				elf_info->relr_relocs = (Elf64_Relr *)dyn->d_un.d_ptr;
				break;
			case DT_PLTRELSZ:
				d_pltrelsz = dyn->d_un.d_val;
				break;
			case DT_STRTAB:
				elf_info->strtab = (char *)dyn->d_un.d_ptr;
				break;
			case DT_SYMTAB:
				elf_info->symtab = (Elf64_Sym *)dyn->d_un.d_ptr;
				break;
			case DT_RELA:
				elf_info->rela_relocs = (Elf64_Rela *)dyn->d_un.d_ptr;
				break;
			case DT_RELASZ:
				d_relasz = dyn->d_un.d_val;
				break;
			case DT_FLAGS_1:
				if((dyn->d_un.d_val & DF_1_NOW) != 0){
					elf_info->flags |= X_ELF_NOW;
				}
				break;
			case DT_VERDEFNUM:
				elf_info->verdef_num = dyn->d_un.d_val;
				break;
			case DT_HIPROC:
				return FALSE;
			case DT_VERDEF:
				have_verdef_num = TRUE;
				elf_info->verdef = (Elf64_Verdef *)dyn->d_un.d_ptr;
				break;
			case DT_VERSYM:
				elf_info->flags |= X_ELF_VERSYM;
				elf_info->versym = (Elf64_Versym *)dyn->d_un.d_ptr;
				break;
			case DT_GNU_HASH:
				gnu_hash = (gnu_hash_table_t *)dyn->d_un.d_ptr;
				break;
			default:
				if(dyn->d_tag > DT_CONFIG){
					return FALSE;
				}
				break;
		}
	}

	if(elf_info->plt_relocs){
		if(d_pltrelsz == -1){
			return FALSE;
		}
		elf_info->flags |= X_ELF_PLTREL;
		elf_info->plt_relocs_num = d_pltrelsz / sizeof(Elf64_Rela);
	}
	if(elf_info->rela_relocs){
		if(d_relasz == -1){
			return FALSE;
		}
		elf_info->flags |= X_ELF_RELA;
		elf_info->rela_relocs_num = d_relasz / sizeof(Elf64_Rela);
	}
	if(elf_info->relr_relocs){
		if(d_relrsz == -1){
			return FALSE;
		}
		elf_info->flags |= X_ELF_RELR;
		elf_info->relr_relocs_num = d_relrsz / sizeof(Elf64_Relr);
	}
	if(elf_info->verdef){
		if(have_verdef_num){
			elf_info->flags |= X_ELF_VERDEF;
		} else {
			elf_info->verdef = NULL;
		}
	}
	if(!elf_info->strtab || !gnu_hash || !elf_info->symtab){
		return FALSE;
	}

	// in case strtab is an offset, in case of MIPS/RISCV (see https://gitlab.gnome.org/GNOME/gnome-shell/-/merge_requests/2718)
	if(UPTR(elf_info->strtab) <= UPTR(ehdr)){
		elf_info->strtab = (char *)PTRADD(ehdr, elf_info->strtab);
		if(elf_info->plt_relocs){
			elf_info->plt_relocs = (Elf64_Rela *)PTRADD(ehdr, elf_info->plt_relocs);
		}
		if(elf_info->rela_relocs){
			elf_info->rela_relocs = (Elf64_Rela *)PTRADD(ehdr, elf_info->rela_relocs);
		}
		if(elf_info->relr_relocs){
			elf_info->relr_relocs = (Elf64_Relr *)PTRADD(ehdr, elf_info->relr_relocs);
		}
		if(elf_info->versym){
			elf_info->versym = (Elf64_Versym *)PTRADD(ehdr, elf_info->versym);
		}
		gnu_hash = (gnu_hash_table_t *)PTRADD(ehdr, gnu_hash);
	}

	// check if verdef is relative, and convert
	if(elf_info->verdef && UPTR(elf_info->verdef) < UPTR(ehdr)){
		elf_info->verdef = (Elf64_Verdef *)PTRADD(ehdr, elf_info->verdef);
	}

	if(elf_info->plt_relocs && !elf_contains_vaddr(elf_info, elf_info->plt_relocs, d_pltrelsz, PF_R)){
		return FALSE;
	}
	if(elf_info->rela_relocs && !elf_contains_vaddr(elf_info, elf_info->rela_relocs, d_relasz, PF_R)){
		return FALSE;
	}
	if(elf_info->relr_relocs && !elf_contains_vaddr(elf_info, elf_info->relr_relocs, d_relrsz, PF_R)){
		return FALSE;
	}
	if(elf_info->verdef && !elf_contains_vaddr(elf_info, elf_info->verdef, sizeof(Elf64_Verdef) * elf_info->verdef_num, PF_R)){
		return FALSE;
	}

	u64 *hash_bloom = &gnu_hash->bloom[0];
	u32 *hash_buckets = (u32 *)&hash_bloom[gnu_hash->bloom_size];
	u32 *hash_chain = &hash_buckets[gnu_hash->nbuckets - gnu_hash->symoffset];

	elf_info->gnu_hash_nbuckets = gnu_hash->nbuckets;
	elf_info->gnu_hash_last_bloom = gnu_hash->bloom_size - 1;
	elf_info->gnu_hash_bloom = hash_bloom;
	elf_info->gnu_hash_bloom_shift = gnu_hash->bloom_shift;
	elf_info->gnu_hash_buckets = hash_buckets;
	elf_info->gnu_hash_chain = hash_chain;
	return TRUE;
}
