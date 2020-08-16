#include <cpp20_http.hpp>

#include <iostream>
#include <array>
#include <filesystem>

//-------------------------------------

using namespace std::string_view_literals;

auto main() -> int {
	try {
		// constexpr auto url = u8"twitter.com"sv;
		constexpr auto url = u8"https://img.webmd.com/dtmcms/live/webmd/consumer_assets/site_images/article_thumbnails/other/cat_relaxing_on_patio_other/1800x1200_cat_relaxing_on_patio_other.jpg";
		auto const response = http::get(url)
			.set_user_agent(u8"GetRequestTest")
			.add_header({.name=u8"One", .value=u8"aaa"}) // http::Header struct.
			.add_headers(u8"Two: bbb") // Can be multiple lines for more than one header.
			.add_headers({
				{.name=u8"Three", .value=u8"ccc"},
				{.name=u8"Four", .value=u8"ddd"},
				{.name=u8"Five", .value=u8"eee"}
			})
			.send();

		auto const response_headers = response.get_headers_string();
		std::cout << "Response headers below.\n\n" << http::util::u8string_to_utf8_string(response_headers) << "\n";

		if (auto const last_modified = response.get_header_value(u8"Last-Modified")) {
			std::cout << "The resource was last modified " << http::util::u8string_to_utf8_string(*last_modified) << '\n';
		}
		else {
			std::cout << "No last-modified header.\n";
		}

		// response.write_content_to_file(std::filesystem::path{url}.filename().string());
		// std::cout << http::util::u8string_to_utf8_string(result.content_as_text()) << '\n';
	}
	catch (http::error::InvalidUrl const&) {
		std::cout << "The url was invalid.\n";
	}
	catch (http::error::ItemNotFound const&) {
		std::cout << "The requested file was not found.\n";
	}
	catch (http::error::ConnectionFailed const& error) {
		std::cout << "The connection failed: ";
		switch (error) {
			// TODO: add using enum declaration when GCC supports it.
			// using enum http::error::ConnectionFailed;
			using namespace http::error;
			case ConnectionFailed::NoInternet:
				std::cout << "there was no internet connection.\n";
				break;
			case ConnectionFailed::Timeout:
				std::cout << "the connection timed out.\n";
				break;
			case ConnectionFailed::Shutdown:
				std::cout << "the connection shut down.\n";
				break;
		}
	}
}
