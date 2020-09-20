#include <iostream>
#include <cpp20_internet_client.hpp>

using namespace internet_client;

auto main() -> int {
	utils::enable_utf8_console();

	try {
		std::cout << "Opening socket...\n";
		auto const socket = open_socket(u8"bjornsundin.com", utils::get_port(utils::Protocol::Http));
		auto buffer = std::array<std::byte, 4096>();

		for (auto i = 0; i < 2; i++) {
			std::cout << "Writing get request to socket...\n";
			while (true) {
				constexpr auto request_string = u8"GET /info/index.html HTTP/1.1\r\nHost: bjornsundin.com\r\n\r\n";
				socket.write(request_string);

				std::cout << "Reading from socket into " << buffer.size() << " bytes long buffer...\n\n";
				
				if (auto const read_result = socket.read(buffer);
					std::holds_alternative<ConnectionWasClosed>(read_result)) 
				{
					std::cout << "The connection was unexpectedly closed by the peer, writing again...\n";
				}
				else {
					std::cout << std::get<DataVector> << " bytes were received:\n\n";
					std::cout << utils::data_to_string<char>(std::span{buffer.data(), read_size}) << "\n\n";
					break;
				}
			}
		}
	}
	catch (errors::ConnectionFailed const&) {
		std::cout << "The connection failed, check your internet connection.\n";
	}
}
