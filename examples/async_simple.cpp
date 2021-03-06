#include <cpp20_internet_client.hpp>

using namespace internet_client;

void handle_progress(http::ResponseProgressRaw const& progress) {
	std::cout << "Received " << progress.data.size() << " bytes.\n";
}

int main() {
	auto response_future = 
		http::make_request(http::RequestMethod::Delete, "https://httpbin.org/delete")
		.add_headers("accept: application/json")
		.set_raw_progress_callback(handle_progress)
		.send_async<256>();

	std::cout << "Waiting...\n";

	http::Response const result = response_future.get();
	std::cout << "Got response!\n";

	std::cout << "The content type is: " << 
		result.get_header_value("content-type").value_or("Unknown") << ".\n";

	std::cout << "Response body:\n" << result.get_body_string() << "\n";
}
