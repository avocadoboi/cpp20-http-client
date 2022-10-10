#include <cpp20_http_client.hpp>

/*
	This example is only meant to compile and demonstrate the socket abstraction.
	You'll have to implement the protocol if it's not http.
*/

int main() {
	// If the last parameter is true, the data is sent and received over TLS.
	auto socket = http_client::open_socket("wss://something", http_client::Port{443}, true);

	// Could also use read_available to only read what is currently 
	// received and ready, and do other stuff while waiting for response data.
	// std::async could be used as well, together with the read function 
	// that takes no parameters and returns a data vector.
	// The result cannot be ignored as it contains the size of data that was actually 
	// read OR http_client::ConnectionClosed if the peer closed the connection.
	auto buffer = std::array<std::byte, 512>{};
	if (auto const result = socket.read(buffer); std::holds_alternative<std::size_t>(result)) 
	{
		// This is the data that we got from this call.
		auto const received_data = std::span{buffer}.first(std::get<std::size_t>(result));
	}
	else {
		// Peer closed the connection!
	}

	// Process buffer, in practice probably in a while loop that 
	// continues until we reached the end of our expected data.

	// Or any contiguous range of std::byte
	socket.write("Some response data");

	// etc...

}
