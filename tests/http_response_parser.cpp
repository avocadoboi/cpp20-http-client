﻿#include "testing_header.hpp"

void test_response_parser(std::string_view const input, algorithms::ParsedResponse const& expected_result) 
{
	auto const response_data = utils::string_to_data<std::byte>(input);

	for (std::size_t const packet_size : {static_cast<std::size_t>(1), static_cast<std::size_t>(8), static_cast<std::size_t>(32), static_cast<std::size_t>(128), static_cast<std::size_t>(512), static_cast<std::size_t>(2048)})
	{
		auto parser = algorithms::ResponseParser{};

		for (auto pos = std::size_t{};; pos += packet_size) 
		{
			if (auto const result = parser.parse_new_data(
					response_data.subspan(pos, std::min(response_data.size() - pos, packet_size))
				))
			{
				REQUIRE(result == expected_result);
				// test_utils::check_http_response(result, expected_result);
				break;
			}
		}
	}
}

utils::DataVector string_to_data_vector(std::string_view const string) {
	auto const data = utils::string_to_data<std::byte>(string);
	return utils::DataVector(data.begin(), data.end());
}

TEST_CASE("Http response parser, conforming line endings") {
	auto const expected_headers_string = std::string{
		"HTTP/1.1 200 OK\r\n"
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

	auto const expected_result = algorithms::ParsedResponse{
		test_utils::ok_status_line,
		expected_headers_string,
		{
			Header{.name="content-length", .value="40"},
			Header{.name="content-type", .value="text/html; charset=UTF-8"},
			Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"}
		},
		string_to_data_vector(expected_body_string),
	};

	test_response_parser(input, expected_result);
}

TEST_CASE("Http response parser, nonconforming line endings") {
	auto const expected_headers_string = std::string{
		"HTTP/1.1 200 OK\n"
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

	auto const expected_result = algorithms::ParsedResponse{
		test_utils::ok_status_line,
		expected_headers_string,
		{
			Header{.name="content-length", .value="40"},
			Header{.name="content-type", .value="text/html; charset=UTF-8"},
			Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"}
		},
		string_to_data_vector(expected_body_string),
	};

	test_response_parser(input, expected_result);
}

TEST_CASE("Http response parser, no body") {
	constexpr auto input = "HTTP/1.1 404 Not Found\r\n\r\n";

	auto const expected_result = algorithms::ParsedResponse{
		StatusLine{
			.http_version = "HTTP/1.1", 
			.status_code = StatusCode::NotFound, 
			.status_message = "Not Found"
		}, 
		"HTTP/1.1 404 Not Found"
	};
	test_response_parser(input, expected_result);
}

TEST_CASE("Http response parser, chunked transfer encoding") {
	auto const expected_headers_string = std::string{
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Date: Sat, 19 Sep 2020 22:49:51 GMT\r\n"
		"transfer-encoding: chunked"
	};
	constexpr auto expected_body_string = "This is a test\nLine two\n\nAnother line!!!";

	constexpr auto chunked_body_string = 
		"1\r\nT"
		"\r\nE\r\n"
		"his is a test\n"
		"\r\nA\r\n"
		"Line two\n\n"
		"\r\nF\r\n"
		"Another line!!!"
		"\r\n0\r\n\r\n";

	auto const input = 
		expected_headers_string + "\r\n\r\n" + chunked_body_string;
		
	auto const expected_result = algorithms::ParsedResponse{
		test_utils::ok_status_line,
		expected_headers_string,
		{
			Header{.name="content-type", .value="text/html; charset=UTF-8"},
			Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"},
			Header{.name="transfer-encoding", .value="chunked"},
		},
		string_to_data_vector(expected_body_string),
	};

	test_response_parser(input, expected_result);
}
