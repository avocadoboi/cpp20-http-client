#include <catch.hpp>

#include <cpp20_internet_client.hpp>

using namespace internet_client;
using namespace std::string_view_literals;

namespace test_utils {

auto const ok_status_line = http::StatusLine{
	.http_version = "HTTP/1.1",
	.status_code = http::StatusCode::Ok,
	.status_message = "OK",
};

} // namespace test_utils
