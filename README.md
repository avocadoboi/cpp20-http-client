# c++20 internet client

c++20 internet client is a (for now) experimental HTTP/FTP client library written in c++20. The library only consists of a single header and cpp source file.

As of now, only gcc supports all of the c++20 features used in this library. Additionally, there are some c++20 features that are not used in the library because no compiler or standard library yet supports them. However the library will be updated over time as compilers start implementing more of c++20.


## Aims
* User friendly, functional design
* An API that is hard to misuse
* All calculations and internal API calls are lazily made and cached
* Library code follows c++ core guidelines
* A single module file when build systems and compilers have good support for modules
* Support for GET and POST requests
* Support for FTP
* Support for Windows, Linux and MacOS. Currently only Windows is supported.

## Simple "GET" request example

```cpp
#include <cpp20_internet_client.hpp>
#include <iostream>

using namespace internet_client;

auto main() -> int {
	try {
		auto const response = http::get("example.com").send();
		response.write_body_to_file("index.html");
	} 
	// Some examples of exceptions that you should handle: 
	catch (errors::ItemNotFound) {
		std::cout << "example.com was taken down???\n";
	}
	catch (errors::ConnectionFailed) {
		std::cout << "The connection failed, maybe you don't have any internet connection :(\n";
	}
}
```

## Development status
The project is in its initial development and only a subset of the functionality has been implemented.
