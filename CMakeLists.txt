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

include_directories("./")
