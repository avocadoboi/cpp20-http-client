#include <iostream>
#include <cpp20_internet_client.hpp>

using namespace internet_client;

auto main() -> int {
	utils::enable_utf8_console();
	
	try {
		auto const socket = open_socket(u8"bjornsundin.com", utils::get_port(utils::Protocol::Http));

		auto const response = socket.send(u8"GET /projects/index.html HTTP/1.1\r\nHost: bjornsundin.com\r\n\r\n");
		std::cout << "Received data from socket:\n";
		std::cout << response.as_string<char>() << '\n';
	}
	catch (errors::ConnectionFailed const& error) {
		std::cout << "The connection failed, check your internet connection.\n";
	}
}
