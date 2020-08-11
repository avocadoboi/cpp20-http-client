cmake_minimum_required(VERSION 3.0.0)
project(cpp20_http VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)

add_executable(cpp20_http cpp20_http.cpp examples/get_request.cpp)

target_include_directories(cpp20_http PRIVATE "./")
