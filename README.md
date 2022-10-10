# C++20 HTTP client

C++20 HTTP client is an HTTP/HTTPS client library written in C++20.

As of now, only GCC and MSVC support all of the C++20 features used in this library. Additionally, there are some C++20 features that are not used in the library because no compiler or standard library yet supports them. However the library will be updated over time as compilers start implementing more of C++20.

## Aims and features
* User friendly, functional design.
* An API that is hard to misuse.
* Library code follows C++ core guidelines.
* A single module file when build systems and compilers have good support for modules. Until then, one source and one header file.
* Safe and easy to use TCP Socket abstraction with support for TLS encryption.
* HTTP requests, both unsecured and over TLS.
* Asynchronous requests.
* Callbacks for inspecting and/or cancelling responses while being received.
* Support for Windows, Linux and MacOS.
* Free from warnings with all useful warning flags turned on.
* Modern CMake integration.
* UTF-8 support.

## Simple "GET" request example
Note that the fmt library is not a dependency of this library, it's just to simplify the example.

See the **examples** directory for more examples.
```cpp
#include <cpp20_http_client.hpp>
#include <fmt/format.h>

int main() {
    try {
        auto const response = http_client::get("https://www.google.com")
            .add_header({.name="HeaderName", .value="header value"})
            .send();
        fmt::print("Date from server: {}.\n", response.get_header_value("date").value_or("Unknown"));
        http_client::utils::write_to_file(response.get_body(), "index.html");
    } 
    catch (http_client::errors::ConnectionFailed const& error) {
        fmt::print("The connection failed - \"{}\"\n", error.what());
    }
}
```

## Dependencies
The only non-native dependency is OpenSSL on Linux and MacOS. It is recommended to use a package manager like VCPKG to install the OpenSSL libraries, especially on MacOS.  

## CMake usage
### Building and installing
You can download, build and install the library as shown below. You only need to do this if you want to use the library as an installation.
```shell
git clone https://github.com/avocadoboi/cpp20-http-client.git
cd cpp20-http-client
mkdir build
cd build
cmake ..
cmake --build . --target cpp20_http_client --config Release
cmake --install .
```
You may want to add some flags to the cmake commands, for example the VCPKG toolchain file or a cmake prefix path for OpenSSL on Linux and MacOS. Use the latest GCC or MSVC compiler to build. You may need to add `sudo` to the install command, or run the command prompt as administrator on Windows.

If you are making changes to the code then use one of the toolchain files in the `cmake` directory to add warning flags. Do this by adding `-DCMAKE_TOOLCHAIN_FILE=cmake/Msvc.cmake` or `-DCMAKE_TOOLCHAIN_FILE=cmake/GccClang.cmake` to the CMake build generation command. These include the VCPKG toolchain file if a `VCPKG_ROOT` environment variable is available.

### Using the installed library
To include the installed library in a CMake project, use find_package like so:
```cmake
find_package(Cpp20HttpClient CONFIG REQUIRED)
target_link_libraries(target_name PRIVATE Cpp20HttpClient::cpp20_http_client)
```
Where target_name is the name of the target to link the library to.

### Using the library as a subproject
You can clone the library into your own project and then use it like so:
```cmake
add_subdirectory(external/cpp20-http-client)
target_link_libraries(target_name PRIVATE Cpp20HttpClient::cpp20_http_client)
```
Where target_name is the name of the target to link the library to. "external/cpp20-http-client" is just an example of where you could put the library in your project.

### Using CMake to download and include the library
You can use the built-in FetchContent CMake module to directly fetch the repository at configure time and link to it:
```cmake
include(FetchContent)

FetchContent_Declare(
    Cpp20HttpClient
    GIT_REPOSITORY https://github.com/avocadoboi/cpp20-http-client.git
)
FetchContent_MakeAvailable(Cpp20HttpClient)

target_link_libraries(target_name PRIVATE Cpp20HttpClient::cpp20_http_client)
```

## Development status
All planned functionality has been implemented and tested. There are some improvements left that are possible and quite big things which may be seen as missing like response caching. These things can easily be extended to the library in the future if there's any need or demand for them. The library will also be updated as more C++20 features become available.
