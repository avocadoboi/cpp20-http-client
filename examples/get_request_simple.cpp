#include <cpp20_internet_client.hpp>

#include <iostream>

using namespace internet_client;

auto main() -> int {
    auto url = std::string{"https://youtube.com"};
    auto response_count = 0;

    while (true) {
        auto const response = http::get(url).send();

        std::cout << "\nheaders " << response_count++ << ": \n" << response.get_headers_string() << '\n';
        // TODO: replace with this when GCC supports std::format
        // utils::println("\nheaders {}: \n{}", response_count++, response.get_headers_string());

        if (response.get_status_code() == http::StatusCode::MovedPermanently) {
            if (auto const new_url = response.get_header_value("location")) 
            {
                url = *new_url;
                continue;
            }
        }
        break;
    }
}
