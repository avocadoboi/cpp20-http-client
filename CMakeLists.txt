cmake_minimum_required(VERSION 3.0.0)
project(cpp20_internet_client VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)

#-----------------------------

if (WIN32)
	link_libraries(Wininet)
endif (WIN32)

#-----------------------------

file(GLOB test_sources tests/*.cpp)
add_executable(cpp20_internet_client_test cpp20_internet_client.cpp ${test_sources})

#-----------------------------

add_executable(cpp20_internet_client cpp20_internet_client.cpp examples/get_request.cpp)

#-----------------------------
# All targets

# Thanks to https://foonathan.net/2018/10/cmake-warnings/
add_compile_options(
	$<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall -Werror -pedantic-errors -Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:/WX /W4>
)
include_directories("./")
