# Toolchain file for MSVC.

add_compile_options(
	/experimental:external
	/external:anglebrackets
	/external:W0 
	/WX 
	/W4
) 

if (DEFINED ENV{VCPKG_ROOT})
	include($ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
endif ()
