#include "testing_header.hpp"

TEST_CASE("utils::concatenate_byte_data with different types of byte data.") {
    auto const expected_result = utils::string_to_data<std::byte>(
        "This is a test of my very own function called \"concatenate_byte_data\". Some numbers: \x5\x9\xA1\xFB."sv
    );
    auto const result = utils::concatenate_byte_data(
        std::byte{u8'T'}, "his"sv, ' ', "is"sv, ' ', "a test of my very "sv, 
        std::array{'o', 'w', 'n', ' '},
        "function called "sv, '\"', u8"concatenate_byte_data"sv, std::byte{'\"'}, std::byte{'.'},
        std::vector{' ', 'S', 'o', 'm', 'e', ' '},
        "numbers: "sv,
        std::array{std::byte{0x5}, std::byte{0x9}, std::byte{0xA1}, std::byte{0xFB}, std::byte{'.'}}
    );
    CHECK(std::ranges::equal(expected_result, result));
}

TEST_CASE("utils::concatenate_byte_data with one argument.") {
    CHECK(std::ranges::equal(utils::concatenate_byte_data("hello"sv), utils::string_to_data<std::byte>("hello"sv)));
}
TEST_CASE("utils::concatenate_byte_data with empty ranges.") {
    CHECK(utils::concatenate_byte_data(""sv, std::vector<std::byte>{}, std::string{}).empty());
}
