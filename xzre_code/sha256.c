/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL sha256(
	const void *data,
	size_t count,
	u8 *mdBuf,
	u64 mdBufSize,
	imported_funcs_t *funcs
){
	if(!data || !count || mdBufSize < SHA256_DIGEST_SIZE || !funcs){
		return FALSE;
	}
	if(!funcs->EVP_Digest || !funcs->EVP_sha256){
		return FALSE;
	}
	const EVP_MD *md = funcs->EVP_sha256();
	if(!md){
		return FALSE;
	}
	return funcs->EVP_Digest(data, count, mdBuf, NULL, md, NULL) == TRUE;
}
