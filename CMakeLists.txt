cmake_minimum_required(VERSION 3.14)
project(xzre LANGUAGES C ASM)

set(CMAKE_C_STANDARD 23)
set(CMAKE_BUILD_TYPE Debug)

find_library(LZMA_LIBRARY NAMES liblzma.a REQUIRED)
message(STATUS "Using ${LZMA_LIBRARY}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_executable(xzre
	${CMAKE_SOURCE_DIR}/liblzma_la-crc64-fast.o
	xzre.c
	xzre.S
	util.c
)
target_link_libraries(xzre ${LZMA_LIBRARY})
target_link_options(xzre PRIVATE -T ${CMAKE_SOURCE_DIR}/xzre.lds)

# disassemble the sample code to compare against the dasm
add_custom_target(xzre_dasm ALL 
	COMMAND objdump
		-M intel
		-j .text
		--disassemble=dasm_sample $<TARGET_FILE:xzre>
		> ${CMAKE_BINARY_DIR}/dasm.txt
)
