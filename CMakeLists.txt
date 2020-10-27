cmake_minimum_required(VERSION 3.18.0)
project(cpp20_internet_client VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin/)

#-----------------------------
# Library target.

add_library(cpp20_internet_client STATIC source/cpp20_internet_client.cpp)
add_library(cpp20_internet_client::cpp20_internet_client ALIAS cpp20_internet_client)

target_compile_features(cpp20_internet_client PUBLIC cxx_std_20)
set_target_properties(cpp20_internet_client PROPERTIES CXX_EXTENSIONS off)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	target_compile_options(cpp20_internet_client PUBLIC
		/experimental:external
		/external:anglebrackets
		/external:W0 
		/WX /Wall
	)
else()
	target_compile_options(cpp20_internet_client PUBLIC
		-Werror -Wall -Wpedantic -Wextra 
		-Wimplicit-fallthrough=5 
		-Wduplicated-branches -Wduplicated-cond 
		-Wcast-qual -Wconversion
		
		-Wno-parentheses
		-Wno-missing-field-initializers
	)
endif()

target_include_directories(cpp20_internet_client PUBLIC "include/")

if (WIN32)
	# Windows sockets 2 and Schannel.
	target_link_libraries(cpp20_internet_client PRIVATE Ws2_32 crypt32)
else()
	# OpenSSL.
	find_package(OpenSSL REQUIRED)
	target_include_directories(cpp20_internet_client PUBLIC "${OPENSSL_INCLUDE_DIR}/../")
	target_link_libraries(cpp20_internet_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

#-----------------------------
# Unit testing target.

file(GLOB test_sources tests/*.cpp)
add_executable(cpp20_internet_client_test source/cpp20_internet_client.cpp ${test_sources})
target_include_directories(cpp20_internet_client_test PRIVATE "external/catch2/")
target_link_libraries(cpp20_internet_client_test PRIVATE cpp20_internet_client)

#-----------------------------
# Example targets.

add_executable(example_get_request source/cpp20_internet_client.cpp examples/get_request.cpp)
target_link_libraries(example_get_request PRIVATE cpp20_internet_client)

add_executable(example_get_request_simple source/cpp20_internet_client.cpp examples/get_request_simple.cpp)
target_link_libraries(example_get_request_simple PRIVATE cpp20_internet_client)

# Not a dependency, but for emergency debugging...
# find_package(fmt CONFIG REQUIRED)
# target_link_libraries(example_get_request_simple PRIVATE fmt::fmt-header-only)
