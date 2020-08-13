#include <cpp20_http.hpp>

#include <iostream>

//-------------------------------------

auto main() -> int {
	// http::get(u8"https://www.google.com/")
	// 	.set_response_listener([=](http::GetResponse&& response) {
	// 		std::cout << response.content_as_text() << '\n';
	// 	}).send();

	try {
		constexpr auto url = u8"https://img.webmd.com/dtmcms/live/webmd/consumer_assets/site_images/article_thumbnails/other/cat_relaxing_on_patio_other/1800x1200_cat_relaxing_on_patio_other.jpg";
		auto const result = http::get(url).send();
		// auto const result = http::get(u8"bjornsundin.com/info/index.html").send();
		result.write_to_file("result.jpg");
		// std::cout << std::string{reinterpret_cast<char const*>(result.content.data()), result.content.size()} << '\n';
	}
	catch (http::error::InvalidUrl const& error) {
		std::cout << "The url was invalid.\n";
	}
	catch (http::error::ItemNotFound const& error) {
		std::cout << "The requested file was not found.\n";
	}
	catch (http::error::ConnectionTimeout const& error) {
		std::cout << "The connection timed out.\n";
	}
	catch (http::error::ConnectionShutdown const& error) {
		std::cout << "The connection shut down.\n";
	}
	catch (std::system_error const& error) {
		std::cout << error.what() << '\n';
	}
}
