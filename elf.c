/**
 * @file elf.c
 * @author Koen Van Bastelaere
 * @brief Elf functions
 * 
 */

#include "xzre.h"

u8 *elf_find_string(elf_info_t *elf_info, EncodedStringId encoded_string_id, u8 *code_start) {
    if (secret_data_append_from_call_site(0xb6, 7, 10, 0) != 0) {
        u64 size = 0;
        u8 *code_current = elf_get_rodata_segment(elf_info, &size);
        if ((code_current != 0) && (size > 0x2b)) {
            u8 *code_end = code_current + size;
            if (code_start != NULL) {
                if (code_end <= code_start)
                    return NULL;
                if (code_current < code_start)
                    code_current = code_start;
            }
            for (; code_current < code_end; ++code_current) {
                EncodedStringId esi = get_string_id(code_current, code_end);
                if (esi != 0) {
                    if (encoded_string_id == 0) {
                        encoded_string_id = esi;
                        return code_current;
                    }
                    if (encoded_string_id == esi)
                        return code_current;
                }
            }
        }
    }
    return NULL;
}

Elf64_Sym *elf_symbol_get_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id)
{
    Elf64_Sym *elf_symbol = elf_symbol_get(elf_info, encoded_string_id, 0);
    if (elf_symbol != NULL) {
        if (((elf_symbol + 8) == 0) || ((elf_symbol + 6) == 0)) {
            elf_symbol = NULL;
        } else {
            elf_symbol = elf_info + elf_symbol + 8;
        }
    }
    return elf_symbol;
}
