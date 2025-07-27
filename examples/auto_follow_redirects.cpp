#include <cpp20_http_client.hpp>
#include <print>

int main() {
	auto const response = http_client::get("google.com")
		.add_headers("Accept: application/json")
		.set_headers_callback([](http_client::ResponseProgressHeaders& headers) {
			if (headers.get_status_code() != http_client::StatusCode::Ok) {
				headers.stop();
			}
		})
		.set_body_progress_callback([](http_client::ResponseProgressBody& body) {
			std::println("Received {} bytes of body data so far.", body.body_data_so_far.size());
		})
		.set_finish_callback([](http_client::Response const& response) {
			std::println("Finished receiving response with status code {}.", static_cast<int>(response.get_status_code()));
		})
		.follow_redirects()
		.send();

	
}
