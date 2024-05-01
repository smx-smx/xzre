/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

struct key_buf {
	u8 key[CHACHA20_KEY_SIZE];
	u8 iv[CHACHA20_IV_SIZE];
};

BOOL secret_data_get_decrypted(u8 *output, global_context_t *ctx){
	if(!output || !ctx || !ctx->imported_funcs){
		return FALSE;
	}
	struct key_buf buf1 = {0}, buf2 = {0};
	if(!chacha_decrypt(
		(u8 *)&buf1, sizeof(buf1),
		buf1.key, buf1.iv,
		(u8 *)&buf2, ctx->imported_funcs)
	){
		return FALSE;
	}

	return chacha_decrypt(
		ctx->secret_data, sizeof(ctx->secret_data),
		buf1.key, buf1.iv,
		output, ctx->imported_funcs);
}
