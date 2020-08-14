#include <cpp20_http.hpp>

#include <iostream>
#include <array>
#include <filesystem>

//-------------------------------------

auto main() -> int {
	// http::get(u8"https://www.google.com/")
	// 	.set_response_listener([=](http::GetResponse&& response) {
	// 		std::cout << response.content_as_text() << '\n';
	// 	}).send();

	try {
		constexpr auto url = u8"twitter.com";
		// constexpr auto url = u8"https://img.webmd.com/dtmcms/live/webmd/consumer_assets/site_images/article_thumbnails/other/cat_relaxing_on_patio_other/1800x1200_cat_relaxing_on_patio_other.jpg";
		auto const result = http::get(url)
			.set_user_agent(u8"GetRequestTest")
			.add_header({.name=u8"One", .value=u8"aaa"})
			.add_headers(u8"Two: bbb")
			.add_headers({
				{.name=u8"Three", .value=u8"ccc"},
				{.name=u8"Four", .value=u8"ddd"},
				{.name=u8"Five", .value=u8"eee"}
			})
			.send();
		result.write_to_file(std::filesystem::path{url}.filename().string());
		std::cout << http::util::u8string_to_utf8_string(result.content_as_text());
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
			using enum http::error::ConnectionFailed;
			case NoInternet:
				std::cout << "there was no internet connection.\n";
				break;
			case Timeout:
				std::cout << "the connection timed out.\n";
				break;
			case Shutdown:
				std::cout << "the connection shut down.\n";
				break;
		}
	}
}
