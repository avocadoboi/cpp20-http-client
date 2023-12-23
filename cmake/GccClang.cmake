# Toolchain file for GCC and Clang.

add_compile_options(
	-Werror
	-Wall
	-Wpedantic
	-Wextra
	-Wcast-qual
	-Wcast-align
	-Wconversion
	-Wsign-conversion
	-Wunused-variable
)

# Only apply the following flags for GNU GCC compiler
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	add_compile_options(
		-Wduplicated-branches
		-Wduplicated-cond
		-fconcepts-diagnostics-depth=2
		-fmax-errors=5
	)
endif ()

if (DEFINED ENV{VCPKG_ROOT})
	include($ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
endif ()
