
add_executable(example_get_request get_request.cpp)
target_link_libraries(example_get_request PRIVATE cpp20_internet_client)

add_executable(example_get_request_simple get_request_simple.cpp)
target_link_libraries(example_get_request_simple PRIVATE cpp20_internet_client)

add_executable(example_async_get_request async_get_request.cpp)
target_link_libraries(example_async_get_request PRIVATE cpp20_internet_client)

add_executable(example_post_request post_request.cpp)
target_link_libraries(example_post_request PRIVATE cpp20_internet_client)

# Not a dependency, but for emergency debugging...
# find_package(fmt CONFIG REQUIRED)
# target_link_libraries(example_get_request_simple PRIVATE fmt::fmt-header-only)
