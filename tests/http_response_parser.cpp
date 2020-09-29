#include "testing_header.hpp"

auto test_response_parser(std::string_view const input, http::algorithms::ParsedResponse const& expected_result) 
	-> void 
{
	auto const response_data = utils::string_to_data<std::byte>(input);

	for (size_t const packet_size : {1, 8, 32, 128, 512, 2048})
	{
		auto parser = http::algorithms::ResponseParser{};

		for (auto pos = std::size_t{};; pos += packet_size) 
		{
			auto const new_data_end = std::min(response_data.begin() + pos + packet_size, response_data.end());
			if (auto const result = parser.parse_new_data(std::span{response_data.begin() + pos, new_data_end}))
			{
				CHECK(result->headers_string == expected_result.headers_string);
				CHECK(std::ranges::equal(result->headers, expected_result.headers));
				CHECK(result->body_data == expected_result.body_data);
				break;
			}
		}
	}
}

auto string_to_data_vector(std::string_view const string) -> utils::DataVector {
	auto const data = utils::string_to_data<std::byte>(string);
	return utils::DataVector(data.begin(), data.end());
}

TEST_CASE("Http response parser, conforming line endings") {
	auto const expected_headers_string = std::string{
		"HTTP/1.1 OK 200\r\n"
		"Content-Length: 40\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Date: Sat, 19 Sep 2020 22:49:51 GMT"
	};
	constexpr auto expected_body_string = 
		"This is a test\n"
		"Line two\n"
		"\n"
		"Another line!!!";

	auto const input = 
		expected_headers_string + "\r\n\r\n" + expected_body_string;

	auto const expected_result = http::algorithms::ParsedResponse{
		.headers_string = expected_headers_string,
		.headers = {
			http::Header{.name="content-length", .value="40"},
			http::Header{.name="content-type", .value="text/html; charset=UTF-8"},
			http::Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"}
		},
		.body_data = string_to_data_vector(expected_body_string),
	};

	test_response_parser(input, expected_result);
}

TEST_CASE("Http response parser, nonconforming line endings") {
	auto const expected_headers_string = std::string{
		"HTTP/1.1 OK 200\n"
		"Content-Length: 40\n"
		"Content-Type: text/html; charset=UTF-8\n"
		"Date: Sat, 19 Sep 2020 22:49:51 GMT"
	};
	constexpr auto expected_body_string = 
		"This is a test\n"
		"Line two\n"
		"\n"
		"Another line!!!";

	auto const input = 
		expected_headers_string + "\n\n" + expected_body_string;

	auto const expected_result = http::algorithms::ParsedResponse{
		.headers_string = expected_headers_string,
		.headers = {
			http::Header{.name="content-length", .value="40"},
			http::Header{.name="content-type", .value="text/html; charset=UTF-8"},
			http::Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"}
		},
		.body_data = string_to_data_vector(expected_body_string),
	};

	test_response_parser(input, expected_result);
}

TEST_CASE("Http response parser, no body") {
	constexpr auto input = "HTTP/1.1 404 Not Found\r\n\r\n";

	auto const expected_result = http::algorithms::ParsedResponse{.headers_string = "HTTP/1.1 404 Not Found"};
	test_response_parser(input, expected_result);
}
