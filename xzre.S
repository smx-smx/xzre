/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
.intel_syntax noprefix
.section .note.GNU-stack,"",%progbits

.section .text
.globl dasm_sample
.globl dasm_sample_end
.globl dasm_sample_dummy_location
.globl secret_data_append_trampoline

/**
  * This function sets up a dummy code block
  * that will pass the backdoor validation rules, so that
  * data shifting is always permitted
  */
secret_data_append_trampoline:
	push rbp
	mov rbp, rsp

	// shift register (edx) from caller (arg1)
	mov edx, edi
	// num of instructions (ecx) from caller (arg2)
	mov ecx, esi

	// code start (dummy code block)
	lea rdi, [rip + 3f]
	// code end (dummy code block)
	lea rsi, [rip + 4f]
	// don't look for a CALL instruction
	xor r8d, r8d
	call secret_data_append_from_function
	// skip the dummy code block
	jmp 4f
	/**
	  * dummy code block to make the validator happy
	  * the number of instructions dictates the maximum number of bitshifts
	  */
3:
	// list of allowed instructions: ADD, SUB, OR, AND, CMP
	// NOTE: MOV instructions are counted, but don't cause any shift
	// list of allowed registers: AX, EAX, RAX, BX, EBX, RBX, CX, ECX, RCX, ECX, RCX
	add cx, cx; sub cx, cx; or cx, cx; and cx, cx; cmp cx, cx
	add cx, cx; sub cx, cx; or cx, cx; and cx, cx; cmp cx, cx
	add cx, cx; sub cx, cx; or cx, cx; and cx, cx; cmp cx, cx
	add cx, cx; sub cx, cx; or cx, cx; and cx, cx; cmp cx, cx
4:
	pop rbp
	ret

dasm_sample:
	endbr64
	push r15
	sub rsp, 0xC0
	add rbp, 1234
	push rdi
	mov edi, 0x85
	push rsi
	mov esi, 0x12
	call secret_data_append_from_call_site
	test eax, eax
	jz 2f

	push rbp
	mov rbp, rsp
	nop
	call dasm_sample_dummy_location
	nop dword ptr [rax+2]
	lea r8, [r9 + 0xbeef]
	xor rbx, rsi
	add edi, [edi+2]
	movdqa  xmm8, xmmword ptr [rsp+0x100]
	inc ax
	call .
2:
	add rsp, 0xc0
	pop rbp
	ret

dasm_sample_end:
	.byte 0

dasm_sample_dummy_location:
	ret