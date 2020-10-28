
add_executable(example_get_request get_request.cpp)
# target_include_directories(example_get_request PRIVATE "../include/")
target_link_libraries(example_get_request PRIVATE cpp20_internet_client)

add_executable(example_get_request_simple get_request_simple.cpp)
# target_include_directories(example_get_request_simple PRIVATE "../include/")
target_link_libraries(example_get_request_simple PRIVATE cpp20_internet_client)

# Not a dependency, but for emergency debugging...
# find_package(fmt CONFIG REQUIRED)
# target_link_libraries(example_get_request_simple PRIVATE fmt::fmt-header-only)
