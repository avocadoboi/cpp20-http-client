#include <cpp20_internet_client.hpp>

#include <chrono>
#include <iostream>

using namespace internet_client;
using namespace std::chrono_literals;

auto main() -> int {
	utils::enable_utf8_console();

    auto const socket = open_socket(u8"www.youtube.com", utils::get_port(utils::Protocol::Https));
    // This is the number of bytes that are read from the socket at a time.
    socket.set_packet_size(128);
    socket.send_async(u8"GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n");
    
    while (!socket.get_is_ready()) {
        auto const data = socket.get_new_data();
        if (!data.empty()) {
            std::cout << response.get_received_size() << " bytes received in total.\n";
            std::cout << data.size() << " new bytes since last time.\n";
            std::cout << utils::data_to_string<char>(data);
        }
        // auto const data = response.get_data();
        std::this_thread::sleep_for(10ms);
    }
}
