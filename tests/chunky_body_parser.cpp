#include "testing_header.hpp"

void test_chunky_body_parser(std::string_view const chunky_body, std::string_view const expected_result) 
{
    auto const chunky_body_data = utils::string_to_data<std::byte>(chunky_body);
    for (auto const packet_size : {1, 8, 32, 128, 512, 2048})
    {
        auto parser = http::algorithms::ChunkyBodyParser{};

        for (auto pos = std::size_t{};; pos += packet_size)
        {
            auto const new_data_end = std::min(chunky_body_data.begin() + pos + packet_size, chunky_body_data.end());
            if (auto const result = parser.parse_new_data(std::span{chunky_body_data.begin() + pos, new_data_end})) {
                CHECK(utils::data_to_string(std::span{*result}) == expected_result);
                break;
            }
        }
    }
}

TEST_CASE("Chunked http body parsing") {
    constexpr auto input = 
        "12\r\n"
        "Hello this is the "
        "\r\n16\r\n"
        "body of some web page "
        "\r\n14\r\n"
        "and it is using the "
        "\r\n1C\r\n"
        "chunked transfer encoding."
        "\r\n"
        "\r\n14\r\n"
        "That was a new line!"
        "\r\n0\r\n"
        "\r\n"sv;
    constexpr auto expected_output =
        "Hello this is the body of some web page and it is using the chunked transfer encoding.\r\n"
        "That was a new line!"sv;

    test_chunky_body_parser(input, expected_output);
}

TEST_CASE("Chunked http body parser, small chunks") {
    constexpr auto input = "1\r\nH\r\n2\r\nel\r\n1\r\nl\r\n1\r\no\r\n0\r\n\r\n"sv;
    constexpr auto expected_output = "Hello"sv;
    test_chunky_body_parser(input, expected_output);
}

TEST_CASE("Chunked http body parser, invalid input") {
    constexpr auto input = "hello world \r\n\r\n19\r\nåäöasdfjkl";
    REQUIRE_THROWS_AS(test_chunky_body_parser(input, ""), errors::ResponseParsingFailed);
}

TEST_CASE("Chunked http body parser, empty input") {
    REQUIRE_THROWS_AS(test_chunky_body_parser("", ""), errors::ResponseParsingFailed);
}
