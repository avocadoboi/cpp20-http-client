#include <cpp20_internet_client.hpp>

using namespace internet_client;

using namespace std::chrono_literals;

int main() {
    auto response = http::get("https://www.youtube.com")
        .set_raw_progress_callback([](http::ResponseProgressRaw& progress) {
            std::cout << "Got " << progress.data.size() << " bytes so far.\n";
        })
        .set_headers_callback([](http::ResponseProgressHeaders& headers) {
            std::cout << "Got headers.\n";
            std::cout << "Status code: " << static_cast<int>(headers.get_status_code()) << '\n';
            if (auto const date = headers.get_header_value("date")) {
                std::cout << "\"date\" header: " << *date << '\n';
            }
            std::cout << "Stopped reading response after headers.\n";
            // Don't continue with reading the body, stop after headers
            headers.stop();
        })
        .send_async();

    // Do stuff that takes time here, while waiting for reponse...
    while (response.wait_for(20ms) != std::future_status::ready) {
        std::cout << "(Waiting for response...)\n";
    }

    std::cout << "Got response!\n";
    
    // Do anything with the http::Response object
    [[maybe_unused]]
    http::Response result = response.get();
}
