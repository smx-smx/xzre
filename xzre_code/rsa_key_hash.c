/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL rsa_key_hash(
	const RSA *rsa,
	u8 *mdBuf,
	u64 mdBufSize,
	imported_funcs_t *funcs
){
	u8 buf[0x100A] = {0};
	u64 written = 0, expSize = 0;
	const BIGNUM *n = NULL, *e = NULL;
	BOOL result = (TRUE
		&& funcs && rsa && funcs->RSA_get0_key
		&& (funcs->RSA_get0_key(rsa, &n, &e, NULL), e != NULL && n != NULL)
		// get bytes of 'e'
		&& bignum_serialize(buf, sizeof(buf), &written, e, funcs)
		&& (expSize = written, written <= 0x1009)
		// get bytes of 'n'
		&& bignum_serialize(buf + written, sizeof(buf) - written, &written, n, funcs)
		&& written + expSize <= sizeof(buf)
		// hash e+n
		&& sha256(buf, written + expSize, mdBuf, mdBufSize, funcs)
	);
	return result;
}