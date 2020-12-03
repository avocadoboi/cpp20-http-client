#include <cpp20_internet_client.hpp>

auto main() -> int {
	auto socket = internet_client::open_socket("wss://something", internet_client::Port{443});
}
