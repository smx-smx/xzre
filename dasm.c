/**
 * @file dasm.c
 * @author Koen Van Bastelaere
 * @brief Dasm functions
 * 
 */

#include "xzre.h"

//  7 = 0x80
//  8 = 0x78
//  9 = 0x70
// 10 = 0x68
// 11 = 0x58
// 12 = 0x50
BOOL find_lea_instruction(u8 *code_start, u8 *code_end, u64 displacement, u64 padding4, u64 padding5, u64 padding6, dasm_ctx_t *ctx, u64 padding8, u64 padding9, u64 padding10, );
{
    int64_t *piVar3;
    uint8_t uVar4;
    uint64_t var_58h;
    int64_t var_50h;

// to check because this is not correct yet    
    uVar4 = 0;
    if (secret_data_append_from_call_site(0x7c, 5, 6, 0) != 0) {
        memset(ctx, 0x00, 0x16);
        piVar3 = piVar3 + uVar4 * -8 + 4;
        for (; code_start < code_end; ++code_start) {
            int iVar1 = x86_dasm(ctx, code_start, code_end);
            if (((iVar1 != 0) && (var_58h == 0x10d) && ((var_6fh & 0x7) == 1)) &&
                (var_50h == displacement || var_50h == -displacement))
                return 1;
        }
    }
    return 0;
}
