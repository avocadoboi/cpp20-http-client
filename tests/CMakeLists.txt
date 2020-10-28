
file(GLOB TEST_SOURCES *.cpp)

add_executable(cpp20_internet_client_test ${TEST_SOURCES})
target_include_directories(cpp20_internet_client_test PRIVATE "../external/catch2/")
# target_include_directories(cpp20_internet_client_test PRIVATE "../include/")
target_link_libraries(cpp20_internet_client_test PRIVATE cpp20_internet_client)

add_test(NAME unit_tests COMMAND cpp20_internet_client_test)
