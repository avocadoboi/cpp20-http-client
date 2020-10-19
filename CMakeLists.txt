cmake_minimum_required(VERSION 3.0.0)
project(cpp20_internet_client VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

#-----------------------------
# Warnings for all targets.

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	add_compile_options(
		/experimental:external
		/external:anglebrackets
		/external:W0 
		/WX /Wall
	)
else()
	add_compile_options(
		-Werror -Wall -Wpedantic -Wextra 
		-Wimplicit-fallthrough=5 
		-Wduplicated-branches -Wduplicated-cond 
		-Wcast-qual -Wconversion
		
		-Wno-parentheses
		-Wno-missing-field-initializers
	)
endif()

#-----------------------------

if (WIN32)
	# Windows sockets 2 and Schannel.
	link_libraries(Ws2_32 crypt32)
else()
	# OpenSSL.
	link_libraries(ssl crypto)
endif()

#-----------------------------
# Unit testing target.

file(GLOB test_sources tests/*.cpp)
add_executable(cpp20_internet_client_test source/cpp20_internet_client.cpp ${test_sources})
target_include_directories(cpp20_internet_client_test PUBLIC "./")

#-----------------------------
# Example target.

add_executable(cpp20_internet_client source/cpp20_internet_client.cpp examples/get_request_simple.cpp)

# find_package(fmt CONFIG REQUIRED)
# target_link_libraries(cpp20_internet_client PRIVATE fmt::fmt-header-only)

#-----------------------------
# All targets.

include_directories("source/")
