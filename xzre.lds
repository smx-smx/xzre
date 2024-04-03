SECTIONS {
    .lzma : {
		"x86_dasm" = .;
        *(.text.x86_codd);
        "find_call_instruction" = .;
        *(.text.lzma_optimum_normaa);
        "find_lea_instruction" = ".";
        *(.text.lzma_raw_encodea);
        "find_function_prologue" = ".";
        *(.text.lzma_raw_coder_memusaga);
        "get_lzma_allocator" = ".";
        *(.text.stream_decoder_memconfia);
        "check_call_site" = ".";
        *(.text.lzma_index_iter_rewina);
        "elf_contains_segment" = ".";
        *(.text.parse_bcz);
        "elf_parse" = ".";
        *(.text.get_literal_prica);
    }
} INSERT AFTER .text;
