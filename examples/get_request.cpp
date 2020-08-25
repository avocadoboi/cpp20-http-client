#include <cpp20_internet_client.hpp>

#include <iostream>
#include <array>
#include <filesystem>

using namespace internet_client;
using namespace std::string_view_literals;

auto read_url() -> std::string {
	std::cout << "Please enter a url: ";
	
	auto url = std::string{};
	std::cin >> url;
	
	std::cout << '\n';

	return url;	
}

auto send_request(std::string_view const url) -> http::GetResponse {
	return http::get(url)
		.set_user_agent("GetRequestTest")
		.add_header({.name="One", .value="aaa"}) // http::Header struct.
		.add_headers("Two: bbb") // Can be multiple lines for more than one header.
		.add_headers( // Variadic template
			http::Header{.name="Three", .value="ccc"},
			http::Header{.name="Four", .value="ddd"},
			http::Header{.name="Five", .value="eee"}
		).add_headers({ // Initializer list
			{.name="Six", .value="fff"},
			{.name="Four", .value="ggg"},
		}).send();
}

auto do_request() -> void {
	auto const url = read_url();
	
	auto const response = send_request(url);

	auto const response_headers = response.get_headers_string();
	std::cout << "Response headers below.\n\n" << response_headers;

	if (auto const last_modified = response.get_header_value("last-modified")) { // Case insensitive
		std::cout << "The resource was last modified " << *last_modified << '\n';
	}
	else {
		std::cout << "No last-modified header.\n";
	}

	if (auto const content_type = response.get_header_value("content-type")) {
		std::cout << "The content type is " << *content_type << '\n';
	}
	else {
		std::cout << "No content-type header.\n";
	}

	auto const filename = [&]{
		if (auto const filename = utils::extract_filename<char>(url); filename.empty()) {
			return utils::split_url<char>(url).domain_name;
		}
		else {
			return filename;
		}
	}();

	std::cout << "Writing body to file with name: " << filename << '\n';
	response.write_body_to_file(std::string{filename});
}

auto main() -> int {
	try {
		do_request();
	}
	catch (errors::InvalidUrl const&) {
		std::cout << "The url was invalid.\n";
	}
	catch (errors::ItemNotFound const&) {
		std::cout << "The requested file was not found.\n";
	}
	catch (errors::ConnectionFailed const& error) {
		std::cout << "The connection failed: ";
		switch (error) {
			// TODO: add using enum declaration when GCC supports it.
			// using enum error::ConnectionFailed;
			using namespace errors;
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

	std::cout << "\n\n";
	std::system("pause");
}
