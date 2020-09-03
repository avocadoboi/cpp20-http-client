#include <iostream>
#include <cpp20_internet_client.hpp>

using namespace internet_client;

auto main() -> int {
	utils::enable_utf8_console();
	
	// try {
		auto const socket = open_socket(u8"youtube.com", utils::get_port(utils::Protocol::Https));

		auto const response = socket.send(u8"GET / HTTP/1.1\r\nHost: youtube.com\r\nuser-agent: Cpp20InternetClient\r\n\r\n");
		std::cout << "Received data from socket:\n";
		std::cout << response.as_string<char>() << '\n';
	// }
	// catch (errors::ConnectionFailed const&) {
	// 	std::cout << "The connection failed, check your internet connection.\n";
	// }
}
