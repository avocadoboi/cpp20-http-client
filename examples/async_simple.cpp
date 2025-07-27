#include <cpp20_http_client.hpp>
#include <print>

void handle_progress(http_client::ResponseProgressRaw const& progress) {
	std::println("Received {} bytes.", progress.data.size());
}

int main() {
	auto response_future = 
		http_client::make_request(http_client::RequestMethod::Delete, "https://httpbin.org/delete")
		.add_headers("accept: application/json")
		.set_raw_progress_callback(handle_progress)
		.send_async<256>();

	std::println("Waiting...");

	http_client::Response const result = response_future.get();
	std::println("Got response!");

	std::println("The content type is: {}.", 
		result.get_header_value("content-type").value_or("Unknown"));

	std::println("Response body:\n{}", result.get_body_string());
}
