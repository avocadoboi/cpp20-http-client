#include "testing_header.hpp"

#include <cmath>

[[nodiscard]]
auto parse_input_in_chunks(algorithms::ResponseParser&& parser, std::string_view const input_string, std::size_t const chunk_size) 
	-> algorithms::ParsedResponse
{
	for (auto pos = std::size_t{};; pos += chunk_size) {
		if (auto result = parser.parse_new_data(
				utils::string_to_data<std::byte>(input_string)
					.subspan(pos, std::min(input_string.size() - pos, chunk_size))
			))
		{
			return *std::move(result);
		}
	}
}

// The parser is tested separately without callbacks, so there's 
// no need to have lots of different types of input here.
// Only the callback system is tested here.
// We do test chunked and non-chunked transfer separately.

auto const headers_string_chunked_transfer = std::string{
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html; charset=UTF-8\r\n"
	"Date: Sat, 19 Sep 2020 22:49:51 GMT\r\n"
	"Transfer-Encoding: chunked"
};
auto const headers_chunked_transfer = std::vector{
	Header{.name="content-type", .value="text/html; charset=UTF-8"},
	Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"},
	Header{.name="transfer-encoding", .value="chunked"},	
};

auto const headers_string_identity_transfer = std::string{
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html; charset=UTF-8\r\n"
	"Date: Sat, 19 Sep 2020 22:49:51 GMT\r\n"
	"Content-Length: 40"
};
auto const headers_identity_transfer = std::vector{
	Header{.name="content-type", .value="text/html; charset=UTF-8"},
	Header{.name="date", .value="Sat, 19 Sep 2020 22:49:51 GMT"},
	Header{.name="content-length", .value="40"},	
};

constexpr auto identity_body_string = "This is a test\nLine two\n\nAnother line!!!"sv;

constexpr auto chunked_body_string = 
	"1\r\nT"
	"\r\nE\r\n"
	"his is a test\n"
	"\r\nA\r\n"
	"Line two\n\n"
	"\r\nF\r\n"
	"Another line!!!"
	"\r\n0\r\n\r\n"sv;
constexpr auto header_body_separator = "\r\n\r\n"sv;

constexpr auto chunk_sizes_to_test = std::array<std::size_t, 5>{1, 8, 32, 128, 512};

void test_callbacks_full_input(
	std::string_view const headers_string,
	std::vector<Header> const& headers,
	std::string_view const body_string
) {
	auto const input_string = (std::string{headers_string} += header_body_separator) += body_string;

	auto const expected_body_data = utils::string_to_data<std::byte const>(identity_body_string);

	auto const expected_result = algorithms::ParsedResponse{
		test_utils::ok_status_line,
		std::string{headers_string},
		headers,
		std::vector(expected_body_data.begin(), expected_body_data.end()),
	};

	for (auto const chunk_size : chunk_sizes_to_test) {
		auto number_of_parsed_packets = std::size_t{};

		auto response_callbacks = algorithms::ResponseCallbacks{
			.handle_raw_progress = [&](ResponseProgressRaw& progress) {
				CHECK(progress.new_data_start == (number_of_parsed_packets * chunk_size));

				auto const input_data = utils::string_to_data<std::byte const>(std::string_view{input_string});
				if (progress.new_data_start + chunk_size > input_data.size()) {
					CHECK(std::ranges::equal(progress.data, input_data));
				}
				else {
					CHECK(std::ranges::equal(progress.data, input_data.first(progress.new_data_start + chunk_size)));
				}

				++number_of_parsed_packets;
            },
			.handle_headers = [&](ResponseProgressHeaders& progress) {
				CHECK(progress.get_status_line() == expected_result.status_line);
				CHECK(progress.get_headers_string() == expected_result.headers_string);
				CHECK(std::ranges::equal(progress.get_headers(), expected_result.headers));
			},
			.handle_body_progress = [&](ResponseProgressBody& progress) {
				CHECK(std::ranges::equal(progress.body_data_so_far, expected_body_data.first(progress.body_data_so_far.size())));
			},
			.handle_finish{},
			.handle_stop{}
		};
		auto const result = parse_input_in_chunks(algorithms::ResponseParser{response_callbacks}, input_string, chunk_size);
		CHECK(result == expected_result);
		CHECK(number_of_parsed_packets <= static_cast<std::size_t>(std::ceil(static_cast<double>(input_string.size()) / static_cast<double>(chunk_size))));
	}
}

TEST_CASE("Response parser with callbacks and chunked transfer, full input") {
	test_callbacks_full_input(headers_string_chunked_transfer, headers_chunked_transfer, chunked_body_string);
}
TEST_CASE("Response parser with callbacks and identity transfer, full input") {
	test_callbacks_full_input(headers_string_identity_transfer, headers_identity_transfer, identity_body_string);
}

void test_callbacks_stopping_after_head(
	std::string_view const headers_string, 
	std::vector<Header> const& headers, 
	std::string_view const body_string
) {
	auto input_string = (std::string{headers_string} += header_body_separator) += body_string;

	auto const expected_result = algorithms::ParsedResponse{
		test_utils::ok_status_line,
		std::string{headers_string},
		headers,
	};
    
    for (auto const chunk_size : chunk_sizes_to_test) {
		auto number_of_parsed_packets = std::size_t{};
		auto got_any_body = false;
        auto response_callbacks = algorithms::ResponseCallbacks{
            .handle_raw_progress = [&](ResponseProgressRaw& progress) {
				CHECK(progress.new_data_start == (number_of_parsed_packets * chunk_size));

				auto const input_data = utils::string_to_data<std::byte const>(std::string_view{input_string});
				if (chunk_size > input_data.size() || progress.new_data_start > input_data.size() - chunk_size) {
					CHECK(std::ranges::equal(progress.data, input_data));
				}
				else {
					CHECK(std::ranges::equal(progress.data, input_data.first(progress.new_data_start + chunk_size)));
				}

                ++number_of_parsed_packets;
            },
			.handle_headers = [&](ResponseProgressHeaders& progress) {
				CHECK(progress.get_parsed_response() == expected_result);
				progress.stop();
			},
			.handle_body_progress = [&](ResponseProgressBody&) {
				got_any_body = true;
			},
			.handle_finish{},
			.handle_stop{}
		};
		CHECK(
			parse_input_in_chunks(algorithms::ResponseParser{response_callbacks}, input_string, chunk_size) ==
			expected_result
		);
		CHECK(!got_any_body);
		CHECK(number_of_parsed_packets == static_cast<std::size_t>(std::ceil(static_cast<double>(headers_string.size() + header_body_separator.size()) / 
			static_cast<double>(chunk_size))));
    }
}

TEST_CASE("Response parser with callbacks and chunked transfer, stopping after head") {
	test_callbacks_stopping_after_head(headers_string_chunked_transfer, headers_chunked_transfer, chunked_body_string);
}
TEST_CASE("Response parser with callbacks and identity transfer, stopping after head") {
	test_callbacks_stopping_after_head(headers_string_identity_transfer, headers_identity_transfer, identity_body_string);
}
