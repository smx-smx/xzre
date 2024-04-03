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
    }
} INSERT AFTER .text;
