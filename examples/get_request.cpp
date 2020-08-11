#include <cpp20_http.hpp>

#include <iostream>

//-------------------------------------

auto main() -> int {
	// http::get(u8"https://www.google.com/")
	// 	.set_response_listener([=](http::GetResponse&& response) {
	// 		std::cout << response.content_as_text() << '\n';
	// 	}).send();

	auto const result = http::get(u8"https://www.google.com/").send();
	
	// std::cout << result.text << '\n';
}
