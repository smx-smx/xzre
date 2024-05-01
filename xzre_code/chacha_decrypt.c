/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <openssl/evp.h>

BOOL chacha_decrypt(
	u8 *in, int inl,
	u8 *key, u8 *iv,
	u8 *out, imported_funcs_t *funcs
){
	int outl = 0;
	if(!in || inl <= 0 || !iv || !out || !funcs) {
		return FALSE;
	}
	if(contains_null_pointers((void **)&funcs->EVP_CIPHER_CTX_new, 6)){
		return FALSE;
	}
	EVP_CIPHER_CTX *ctx = funcs->EVP_CIPHER_CTX_new();
	if(!ctx){
		return FALSE;
	}
	const EVP_CIPHER *cipher = EVP_chacha20();
	if(funcs->EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == TRUE
	  && funcs->EVP_DecryptUpdate(ctx, out, &outl, in, inl) == TRUE
	  && outl >= 0
	){
		if(funcs->EVP_DecryptFinal_ex(ctx, &out[outl], &outl) == TRUE
		 && outl >= 0 && inl >= outl
		){
			funcs->EVP_CIPHER_CTX_free(ctx);
			return TRUE;
		}
	}
	if(funcs->EVP_CIPHER_CTX_free){
		funcs->EVP_CIPHER_CTX_free(ctx);
	}
	return FALSE;
}