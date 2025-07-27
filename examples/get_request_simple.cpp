#include <cpp20_http_client.hpp>
#include <print>

int main() {
    auto url = std::string{};
    std::print("Please enter a URL: ");
    std::cin >> url;

    auto response_count = 0;

    while (true) {
        auto const response = http_client::get(url)
            .set_headers_callback([](http_client::ResponseProgressHeaders& headers) {
                // If you want to ignore the body when the status code is not OK.
                if (headers.get_status_code() != http_client::StatusCode::Ok) {
                    headers.stop();
                }
            })
            .send();

        std::println("\nHeaders {}: \n{}", response_count++, response.get_headers_string());

        if (response.get_status_code() == http_client::StatusCode::MovedPermanently ||
            response.get_status_code() == http_client::StatusCode::Found) 
        {
            if (auto const new_url = response.get_header_value("location")) {
                url = *new_url;
                continue;
            }
        }
        else {
            std::println("\nBody:\n{}", response.get_body_string());
        }
        break;
    }
}
