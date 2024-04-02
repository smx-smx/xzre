/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
.intel_syntax noprefix
.section .note.GNU-stack,"",%progbits

.section .text
.globl dasm_sample
.globl dasm_sample_end

dasm_sample:
	nop
	nop dword ptr [rax+2]
	xor rbx, rsi
	add edi, [edi+2]
	movdqa  xmm8, xmmword ptr [rsp+0x100]
	inc ax
	call .
	ret

dasm_sample_end:
	.byte 0