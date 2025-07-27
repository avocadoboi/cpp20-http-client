#include <cpp20_http_client.hpp>
#include <print>

using namespace std::chrono_literals;

int main() {
    auto response = http_client::get("https://www.youtube.com")
        .set_raw_progress_callback([](http_client::ResponseProgressRaw const& progress) {
            std::println("Got {} bytes so far.", progress.data.size());
        })
        .set_headers_callback([](http_client::ResponseProgressHeaders& headers) {
            std::println("Got headers.");
            
            std::println("Status code: {}", static_cast<int>(headers.get_status_code()));
            if (auto const date = headers.get_header_value("date")) {
                std::println("\"date\" header: {}", *date);
            }
            
            std::println("Stopped reading response after headers.");
            
            // Don't continue with reading the body, stop after headers
            headers.stop();
        })
        .send_async<1024>();

    // Do stuff that takes time here, while waiting for response...
    while (response.wait_for(20ms) != std::future_status::ready) {
        std::println("(Waiting for response...)");
    }

    std::println("Got response!\n");
    
    // Do anything with the Response object
    http_client::Response const result = response.get();

    for (auto const [name, value] : result.get_headers()) {
        std::println("\"{}\" header has value \"{}\".", name, value);
    }

    std::println("Response body empty? {}", result.get_body_string().empty() ? "Yes" : "No");
}
