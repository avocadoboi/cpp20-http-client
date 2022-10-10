
file(GLOB TEST_SOURCES *.cpp)

add_executable(cpp20_http_client_test ${TEST_SOURCES})

target_link_libraries(cpp20_http_client_test PRIVATE cpp20_http_client)

find_package(Catch2 CONFIG REQUIRED)
target_link_libraries(cpp20_http_client_test PRIVATE Catch2::Catch2 Catch2::Catch2WithMain)

add_test(NAME unit_tests COMMAND cpp20_http_client_test)
