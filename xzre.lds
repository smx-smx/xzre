SECTIONS {
    .lzma : {
		"x86_dasm" = .;
        *(.text.x86_codd);
    }
} INSERT AFTER .text;
