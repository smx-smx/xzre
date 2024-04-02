SECTIONS {
    .lzma : {
		"x86_dasm" = .;
        *(.text.x86_codd);
        "find_call_instruction" = .;
        *(.text.lzma_optimum_normaa);
    }
} INSERT AFTER .text;
