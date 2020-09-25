#include "testing_header.hpp"

auto test_chunky_body_parser(std::string_view const chunky_body, std::string_view const expected_result) 
    -> void 
{
    auto const chunky_body_data = utils::string_to_data<std::byte>(chunky_body);
    for (auto const packet_size : {1, 8, 32, 128, 512, 2048})
    {
        auto parser = http::ChunkyBodyParser{};

        for (auto pos = std::size_t{};; pos += packet_size)
        {
            auto const new_data_end = std::min(chunky_body_data.begin() + pos + packet_size, chunky_body_data.end());
            if (auto const result = parser.parse_new_data(std::span{chunky_body_data.begin() + pos, new_data_end})) {
                CHECK(utils::data_to_string<char>(std::span{*result}) == expected_result);
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
        "\r\n1B\r\n"
        "chunked transfer encoding."
        "\r\n"
        "\r\n14\r\n"
        "That was a new line!"sv;
    constexpr auto expected_output =
R"(Hello this is the body of some web page and it is using the chunked transfer encoding.
That was a new line!)"sv;

    test_chunky_body_parser(input, expected_output);
}
