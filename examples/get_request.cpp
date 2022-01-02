#include <cpp20_internet_client.hpp>

using namespace internet_client;
using namespace std::string_view_literals;

std::string read_url() {
	std::cout << "Please enter a url: ";
	
	auto url = std::string{};
	std::cin >> url;
	
	std::cout << '\n';

	return url;	
}

http::Response send_request(std::string_view const url) {
	return http::get(url)
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

void use_response(http::Response const& response) {
	auto const response_headers = response.get_headers_string();
	std::cout << "Response headers below.\n\n" << response_headers << "\n\n";

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

	auto const url = response.get_url();

	auto const filename = [&]{
		if (auto const filename = utils::extract_filename(url); filename.empty()) {
			return utils::split_url(url).host;
		}
		else {
			return filename;
		}
	}();

	std::cout << "Writing body to file with name: " << filename << '\n';
	utils::write_to_file(response.get_body(), std::string{filename});
}

http::Response do_request() {
	auto url = read_url();

	while (true) {
		auto response = send_request(url);

		// Handle possible TLS redirect
		if (response.get_status_code() == http::StatusCode::MovedPermanently||
            response.get_status_code() == http::StatusCode::Found) 
		{
			if (auto const new_url = response.get_header_value("location")) {
				std::cout << "Got status code moved permanently or found, redirecting to " << *new_url << "...\n\n";
				url = *new_url;
				continue;
			}
		}
		return response;
	}
}

int main() {
	try {
		auto const response = do_request();
		use_response(response);
	}
	catch (errors::ConnectionFailed const& error) {
		std::cout << "The connection failed with error \"" << error.what() << '"';
	}

	std::cout << "\n\n";
}
