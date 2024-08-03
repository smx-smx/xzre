add_library(xzre_code
	backdoor_entry.c
	chacha_decrypt.c
	count_bits.c
	count_pointers.c
	elf_parse.c
	elf_symbol_get_addr.c
	get_lzma_allocator.c
	find_lea_instruction.c
	find_string_reference.c
	is_endbr64_instruction.c
	init_elf_entry_ctx.c
	fake_lzma_alloc.c
	fake_lzma_free.c
	find_function.c
	main_elf_parse.c
	rsa_key_hash.c
	run_backdoor_commands.c
	secret_data_append_from_address.c
	secret_data_append_item.c
	secret_data_append_singleton.c
	secret_data_get_decrypted.c
	sha256.c
	sshd_patch_variables.c
	update_got_offset.c
	update_cpuid_got_index.c
)
target_compile_options(xzre_code PRIVATE
	-Os -fomit-frame-pointer
)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/xzre_merged.o
	DEPENDS $<TARGET_OBJECTS:xzre_code>
	COMMAND ${CMAKE_LINKER}
		-relocatable $<TARGET_OBJECTS:xzre_code>
		-o ${CMAKE_BINARY_DIR}/xzre_merged.o
	COMMAND_EXPAND_LISTS
	VERBATIM
)

add_custom_target(make_object_file ALL
	DEPENDS ${CMAKE_BINARY_DIR}/xzre_merged.o
)
add_dependencies(make_object_file xzre_code)
