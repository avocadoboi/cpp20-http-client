cmake_minimum_required(VERSION 3.0.0)
project(cpp20_internet_client VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

#-----------------------------

if (WIN32)
	# Windows sockets 2
	link_libraries(Ws2_32)
else()
	# OpenSSL
	link_libraries(ssl crypto)
endif()

#-----------------------------

file(GLOB test_sources tests/*.cpp)
add_executable(cpp20_internet_client_test cpp20_internet_client.cpp ${test_sources})

#-----------------------------

add_executable(cpp20_internet_client cpp20_internet_client.cpp examples/sockets.cpp)

#-----------------------------
# All targets

# Thanks to https://foonathan.net/2018/10/cmake-warnings/
add_compile_options(
	$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall -Werror -pedantic-errors -Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:/WX /W4>
)
include_directories("./")
