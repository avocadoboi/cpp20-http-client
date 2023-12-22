#include <cpp20_http_client.hpp>

void handle_progress(http_client::ResponseProgressRaw const& progress) {
	std::cout << "Received " << progress.data.size() << " bytes.\n";
}

int main() {
	auto response_future = 
		http_client::make_request(http_client::RequestMethod::Delete, "https://httpbin.org/delete")
		.add_headers("accept: application/json")
		.set_raw_progress_callback(handle_progress)
		.send_async<256>();

	std::cout << "Waiting...\n";

	http_client::Response const result = response_future.get();
	std::cout << "Got response!\n";

	std::cout << "The content type is: " << 
		result.get_header_value("content-type").value_or("Unknown") << ".\n";

	std::cout << "Response body:\n" << result.get_body_string() << "\n";
}
