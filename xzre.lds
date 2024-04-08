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

        "find_function" = ".";
        *(.text.lzma2_encoder_inia);

        "get_lzma_allocator" = ".";
        *(.text.stream_decoder_memconfia);

        "secret_data_append_from_call_site" = ".";
        *(.text.lzma_index_iter_rewina);

        "elf_contains_vaddr" = ".";
        *(.text.parse_bcz);

        "elf_parse" = ".";
        *(.text.get_literal_prica);

        "main_elf_parse" = ".";
        *(.text.lzma_filter_decoder_is_supportea);

        "elf_symbol_get" = ".";
        *(.text.crc_inia);

        "elf_symbol_get_addr" = ".";
        *(.text.crc64_generia);

        "elf_get_code_segment" = ".";
        *(.text.lzma_check_updata);

        "elf_get_rodata_segment" = ".";
        *(.text.index_tree_appena);

        "elf_get_data_segment" = ".";
        *(.text.microlzma_decoda);

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

        "backdoor_init" = ".";
        *(.text._get_cpuia);

        "backdoor_init_stage2" = ".";
        *(.text.lzma_validate_chaia);

        "backdoor_setup" = ".";
        *(.text.microlzma_encoder_inia);

        "resolve_libc_imports" = ".";
        *(.text.lzma_index_buffer_encoda);

        "process_shared_libraries" = ".";
        *(.text.lzma_index_stream_flaga);

        "process_shared_libraries_map" = ".";
        *(.text.lzma_index_encoder_inia);

        "chacha_decrypt" = ".";
        *(.text.lzma_delta_encoder_inia);

        "secret_data_get_decrypted" = ".";
        *(.text.parse_lzma10);

        "is_range_mapped" = ".";
        *(.text.hc_find_funa);

        "elf_find_string_references" = ".";
        *(.text.auto_decoder_iniz);

        "get_string_id" = ".";
        *(.text.simple_coder_updata);

        "init_hook_functions" = ".";
        *(.text.lzma_delta_decoder_inis);

        "_get_cpuid" = ".";
        *(.text._get_cpuid);

        "update_got_address" = ".";
        *(.text.lzma_stream_header_encoda);
    }
} INSERT AFTER .text;

SECTIONS {
    .lzma_bss : {
        "global_ctx" = ".";
        *(.bss.lzma12_codez);

        "resolver_call_count" = ".";
        *(.bss.__intr2);
    }
} INSERT AFTER .bss;

SECTIONS {
    .lzma_data_relro : {
        "fake_lzma_allocator" = ".";
        *(.data.rel.ro.decoders0);
    }
} INSERT AFTER .data.rel.ro;