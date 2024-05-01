cmake_minimum_required(VERSION 3.24)
project(xzre LANGUAGES C ASM)

set(CMAKE_C_STANDARD 23)
set(CMAKE_BUILD_TYPE Debug)

find_library(UNWIND_LIBRARY NAMES libunwind.so REQUIRED)
find_library(LZMA_LIBRARY NAMES liblzma.a REQUIRED)
find_program(SED_COMMAND NAMES sed REQUIRED)
message(STATUS "Using ${LZMA_LIBRARY}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wno-deprecated-declarations -Wno-address-of-packed-member)

add_executable(xzre)
add_library(lzma SHARED)

if(USE_PHP)
	find_program(PHP_CONFIG_EXECUTABLE NAMES
		php-config
		HINTS
			# use php-config from the sysroot (it's a shell script)
			${CMAKE_SYSROOT}
		PATH_SUFFIXES
			bin
			usr/bin
		REQUIRED
	)
	message(STATUS "php-config: ${PHP_CONFIG_EXECUTABLE}")
	execute_process(
		COMMAND ${PHP_CONFIG_EXECUTABLE} --includes
		OUTPUT_VARIABLE PHP_INCLUDE_DIRS OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	execute_process(
		COMMAND ${PHP_CONFIG_EXECUTABLE} --libs
		OUTPUT_VARIABLE PHP_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	string(REPLACE "-I" "" PHP_INCLUDE_DIRS ${PHP_INCLUDE_DIRS})
	separate_arguments(PHP_INCLUDE_DIRS)

	string(REPLACE "-l" "" PHP_LIBS ${PHP_LIBS})
	separate_arguments(PHP_LIBS)

	find_library(PHP_EMBED_LIBRARY NAMES php REQUIRED)
endif()

set(SOURCES
	${CMAKE_SOURCE_DIR}/liblzma_la-crc64-fast.o
	xzre.c
	xzre.S
	util.c
)

add_subdirectory(xzre_code)
target_include_directories(xzre_code PRIVATE ${CMAKE_SOURCE_DIR})

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/xzre.lds
	COMMAND ${CMAKE_C_COMPILER} -x c -E -P ${CMAKE_SOURCE_DIR}/xzre.lds.in > ${CMAKE_BINARY_DIR}/xzre.lds
	DEPENDS ${CMAKE_SOURCE_DIR}/xzre.lds.in
	VERBATIM
)
add_custom_target(gen_lds DEPENDS ${CMAKE_BINARY_DIR}/xzre.lds)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/xzre.csv
	COMMAND ${CMAKE_C_COMPILER}
		-DGEN_CSV -x c -E -P
		${CMAKE_SOURCE_DIR}/xzre.lds.in | ${SED_COMMAND} "/^\\s*$/d;s/^\\s*//" > ${CMAKE_BINARY_DIR}/xzre.csv
	DEPENDS ${CMAKE_SOURCE_DIR}/xzre.lds.in
	VERBATIM
)
add_custom_target(gen_csv ALL DEPENDS ${CMAKE_BINARY_DIR}/xzre.csv)


target_sources(xzre PRIVATE ${SOURCES})
target_sources(lzma PRIVATE ${SOURCES})
target_compile_definitions(lzma PRIVATE XZRE_SHARED)

if(USE_PHP)
	target_compile_definitions(xzre PRIVATE USE_PHP)
	target_compile_definitions(lzma PRIVATE USE_PHP)
	target_include_directories(xzre PRIVATE ${PHP_INCLUDE_DIRS})
	target_include_directories(lzma PRIVATE ${PHP_INCLUDE_DIRS})
	target_link_libraries(xzre ${PHP_EMBED_LIBRARY})
	target_link_libraries(lzma ${PHP_EMBED_LIBRARY})
endif()

target_link_libraries(xzre ${LZMA_LIBRARY})
target_link_libraries(lzma "$<LINK_LIBRARY:WHOLE_ARCHIVE,${LZMA_LIBRARY}>")

target_link_options(xzre PRIVATE "LINKER:--no-undefined")
target_link_options(lzma PRIVATE
	"LINKER:--no-undefined"
	"LINKER:--version-script=${CMAKE_SOURCE_DIR}/xzre.ver")

target_link_options(xzre PRIVATE -T ${CMAKE_BINARY_DIR}/xzre.lds)
target_link_options(lzma PRIVATE -T ${CMAKE_BINARY_DIR}/xzre.lds)
add_dependencies(xzre gen_lds)
add_dependencies(lzma gen_lds)

# disassemble the sample code to compare against the dasm
add_custom_target(xzre_dasm ALL 
	COMMAND objdump
		-M intel
		-j .text
		--disassemble=dasm_sample $<TARGET_FILE:xzre>
		> ${CMAKE_BINARY_DIR}/dasm.txt
)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/xzre.h
	COMMAND ${CMAKE_C_COMPILER} -DXZRE_SLIM 
		-P -E ${CMAKE_SOURCE_DIR}/xzre.h
		-D "static_assert(x)="
		| ${SED_COMMAND} "/^;*$/d" > ${CMAKE_BINARY_DIR}/xzre.h
	DEPENDS ${CMAKE_SOURCE_DIR}/xzre.h
	VERBATIM
)
add_custom_target(gen_xzre_header ALL DEPENDS ${CMAKE_BINARY_DIR}/xzre.h)


add_library(ssh_patch SHARED ssh_patch.c ssh_patch.S)
target_compile_options(ssh_patch PRIVATE -Wno-deprecated-declarations)
target_link_libraries(ssh_patch crypto dl ${UNWIND_LIBRARY})
