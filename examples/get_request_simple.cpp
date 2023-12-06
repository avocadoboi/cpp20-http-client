#include <cpp20_http_client.hpp>

using namespace http_client;

int main() {
    auto url = std::string{};
    std::cout << "Please enter a URL: ";
    std::cin >> url;

    auto response_count = 0;

    while (true) {
        auto const response = get(url).send();

        std::cout << "\nHeaders " << response_count++ << ": \n" << response.get_headers_string() << '\n';
        // TODO: replace with this when GCC supports std::format
        // utils::println("\nHeaders {}: \n{}", response_count++, response.get_headers_string());

        if (response.get_status_code() == http_client::StatusCode::MovedPermanently ||
            response.get_status_code() == http_client::StatusCode::Found) 
        {
            if (auto const new_url = response.get_header_value("location")) {
                url = *new_url;
                continue;
            }
        }
        else {
            std::cout << "\nBody:\n" << response.get_body_string() << '\n';
        }
        break;
    }
}
