cmake_minimum_required(VERSION 3.0.0)
project(cpp20_http VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)

#-----------------------------

file(GLOB test_sources tests/*.cpp)
add_executable(cpp20_http_test cpp20_http.cpp ${test_sources})

#-----------------------------

add_executable(cpp20_http cpp20_http.cpp examples/get_request.cpp)

#-----------------------------
# All targets

include_directories("./")
