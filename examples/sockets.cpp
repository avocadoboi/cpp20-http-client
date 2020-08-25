#include <iostream>
#include <cpp20_internet_client.hpp>

using namespace internet_client;

auto main() -> int {
	utils::enable_utf8_console();
	
	auto const socket = open_socket(u8"bjornsundin.com", utils::get_protocol_port(utils::Protocol::Http));
	socket.send_string(u8"GET /projects/index.html HTTP/1.1\r\nHost: bjornsundin.com\r\n\r\n");
	auto const response = socket.receive_string();
	
	std::cout << "Read response:\n";
	std::cout << utils::u8string_to_utf8_string(response) << '\n';
}
