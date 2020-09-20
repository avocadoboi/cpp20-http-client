#include <cpp20_internet_client.hpp>

#include <chrono>
#include <iostream>

using namespace internet_client;
using namespace std::chrono_literals;

auto main() -> int {
	utils::enable_utf8_console();

    auto socket = open_socket(u8"www.youtube.com", utils::get_port(utils::Protocol::Https));

    std::cout << "Requesting youtube.com...\n";
    socket.write(u8"GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n");
    
    while (!socket.get_is_closed()) {
        auto const data = socket.read_available();
        if (!data.empty()) {
            std::cout << socket.get_received_size() << " bytes received in total.\n";
            std::cout << data.size() << " new bytes since last time.\n";
            // std::cout << utils::data_to_string<char>(std::span{data.begin(), data.end()});
        }
        std::this_thread::sleep_for(10ms);
    }
}
