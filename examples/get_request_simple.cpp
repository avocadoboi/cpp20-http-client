#include <cpp20_internet_client.hpp>

#include <iostream>

namespace http = internet_client::http;

auto main() -> int {
    auto url = std::string{"youtube.com"};
    auto response_count = 0;

    while (true) {
        auto const response = http::get(url).send();
        std::cout << "\nheaders " << response_count++ << ": \n" << response.get_headers_string() << '\n';

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
