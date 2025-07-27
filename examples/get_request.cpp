#include <cpp20_http_client.hpp>
#include <print>

using namespace std::string_view_literals;

std::string read_url() {
	std::print("Please enter a url: ");
	
	auto url = std::string{};
	std::cin >> url;
	
	std::println();

	return url;	
}

http_client::Response send_request(std::string_view const url) {
	return http_client::get(url)
		.add_header({.name="One", .value="aaa"}) // Header struct.
		.add_headers("Two: bbb") // Can be multiple lines for more than one header.
		.add_headers( // Variadic template
			http_client::Header{.name="Three", .value="ccc"},
			http_client::Header{.name="Four", .value="ddd"},
			http_client::Header{.name="Five", .value="eee"}
		).add_headers({ // Initializer list
			{.name="Six", .value="fff"},
			{.name="Four", .value="ggg"},
		}).set_headers_callback([](http_client::ResponseProgressHeaders& headers) {
			if (headers.get_status_code() == http_client::StatusCode::Ok) {
				std::println("Got status code 200 OK, continuing to read body...");
			}
			else {
				std::println("Got status code {}, stopping reading body.", static_cast<int>(headers.get_status_code()));
				headers.stop(); // Stop reading the body if the status code is not OK.
			}
		}).send();
}

void use_response(http_client::Response const& response) {
	auto const response_headers = response.get_headers_string();
	std::println("Response headers below.\n\n{}\n", response_headers);

	if (auto const last_modified = response.get_header_value("last-modified")) { // Case insensitive
		std::println("The resource was last modified {}", *last_modified);
	}
	else {
		std::println("No last-modified header.");
	}

	if (auto const content_type = response.get_header_value("content-type")) {
		std::println("The content type is {}", *content_type);
	}
	else {
		std::println("No content-type header.");
	}

	auto const url = response.get_url();

	auto const filename = [&]{
		if (auto const filename = http_client::utils::extract_filename(url); filename.empty()) {
			return http_client::utils::split_url(url).host;
		}
		else {
			return filename;
		}
	}();

	std::println("Writing body to file with name: {}", filename);
	http_client::utils::write_to_file(response.get_body(), std::string{filename});
}

http_client::Response do_request() {
	auto url = read_url();

	while (true) {
		auto response = send_request(url);

		// Handle possible TLS redirect
		if (response.get_status_code() == http_client::StatusCode::MovedPermanently||
			response.get_status_code() == http_client::StatusCode::Found)
		{
			if (auto const new_url = response.get_header_value("location")) {
				std::println("Got status code moved permanently or found, redirecting to {}...\n", *new_url);
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
	catch (http_client::errors::ConnectionFailed const& error) {
		std::println("The connection failed with error \"{}\"", error.what());
	}

	std::print("\n\n");
}
