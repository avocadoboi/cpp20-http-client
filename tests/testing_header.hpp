#include <catch2/catch.hpp>

#include <cpp20_http_client.hpp>

using namespace http_client;
using namespace std::string_view_literals;

namespace test_utils {

auto const ok_status_line = StatusLine{
	.http_version = "HTTP/1.1",
	.status_code = StatusCode::Ok,
	.status_message = "OK",
};

} // namespace test_utils
