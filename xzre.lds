SECTIONS {
    .lzma_text : {
        "x86_dasm" = .;
        *(.text.x86_codd);

        "find_call_instruction" = .;
        *(.text.lzma_optimum_normaa);

        "find_lea_instruction" = ".";
        *(.text.lzma_raw_encodea);

        "find_instruction_with_mem_operand" = ".";
        *(.text.stream_encoder_mt_inia);

        "find_lea_instruction_with_mem_operand" = ".";
        *(.text.lzma_mt_block_siza);

        "find_instruction_with_mem_operand_ex" = ".";
        *(.text.lzma_properties_siza);

        "find_function_prologue" = ".";
        *(.text.lzma_raw_coder_memusaga);

        "find_function_prologue_ex" = ".";
        *(.text.lzma2_encoder_inia);

        "get_lzma_allocator" = ".";
        *(.text.stream_decoder_memconfia);

        "secret_data_append_from_call_site" = ".";
        *(.text.lzma_index_iter_rewina);

        "elf_contains_vaddr" = ".";
        *(.text.parse_bcz);

        "elf_parse" = ".";
        *(.text.get_literal_prica);

        "elf_symbol_get" = ".";
        *(.text.crc_inia);

        "elf_symbol_get_addr" = ".";
        *(.text.crc64_generia);

        "elf_get_code_segment" = ".";
        *(.text.lzma_check_updata);

        "elf_get_plt_symbol" = ".";
        *(.text.delta_coder_ena);

        "elf_get_got_symbol" = ".";
        *(.text.delta_decoda);

        "elf_get_reloc_symbol" = ".";
        *(.text.lz_encoda);

        "elf_find_string" = ".";
        *(.text.lzip_decoda);

        "elf_find_string_reference" = ".";
        *(.text.lzma_auto_decoda);

        "secret_data_append_from_instruction" = ".";
        *(.text.lzma_lzma_encoder_inia);

        "secret_data_append_from_code" = ".";
        *(.text.lzma_memlimit_gea);

        "secret_data_append_if_flags" = ".";
        *(.text.lzma_check_inia);

        "find_reg2reg_instruction" = ".";
        *(.text.lzma_block_total_siza);

        "find_string_reference" = ".";
        *(.text.stream_encoda);

        "secret_data_append_singleton" = ".";
        *(.text.rc_read_inis);

        "backdoor_setup" = ".";
        *(.text.microlzma_encoder_inia);

        "resolve_libc_imports" = ".";
        *(.text.lzma_index_buffer_encoda);
    }
} INSERT AFTER .text;

SECTIONS {
    .lzma_bss : {
        "global_ctx" = ".";
        *(.bss.lzma12_codez);
    }
} INSERT AFTER .bss;
