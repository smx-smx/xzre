/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
.intel_syntax noprefix
.section .note.GNU-stack,"",%progbits

.section .text
.globl dasm_sample
.globl dasm_sample_end
.globl dasm_sample_dummy_location

dasm_sample:
	nop
	call dasm_sample_dummy_location
	nop dword ptr [rax+2]
	lea r8, [r9 + 0xbeef]
	xor rbx, rsi
	add edi, [edi+2]
	movdqa  xmm8, xmmword ptr [rsp+0x100]
	inc ax
	call .
	ret

dasm_sample_end:
	.byte 0

dasm_sample_dummy_location:
	ret