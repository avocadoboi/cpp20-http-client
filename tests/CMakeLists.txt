
file(GLOB TEST_SOURCES *.cpp)

add_executable(cpp20_http_client_test ${TEST_SOURCES})

target_link_libraries(cpp20_http_client_test PRIVATE cpp20_http_client)

find_package(Catch2 CONFIG REQUIRED)
target_link_libraries(cpp20_http_client_test PRIVATE Catch2::Catch2 Catch2::Catch2WithMain)
target_include_directories(cpp20_http_client_test PRIVATE ${Catch2_INCLUDE_DIRS})

add_test(NAME unit_tests COMMAND cpp20_http_client_test)

add_custom_target(run_tests
  COMMAND ${CMAKE_BINARY_DIR}/bin/cpp20_http_client_test --use-colour yes
  DEPENDS cpp20_http_client_test
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  COMMENT "Running tests..."
)
