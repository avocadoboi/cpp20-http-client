#include "testing_header.hpp"

TEST_CASE("uri_encode with std::u8string_view #1") {
    REQUIRE(utils::uri_encode(u8"https://ja.wikipedia.org/wiki/パーセントエンコーディング"sv) == 
        u8"https://ja.wikipedia.org/wiki/%e3%83%91%e3%83%bc%e3%82%bb%e3%83%b3%e3%83%88%e3%82%a8%e3%83%b3%e3%82%b3%e3"
        "%83%bc%e3%83%87%e3%82%a3%e3%83%b3%e3%82%b0");
}
TEST_CASE("uri_encode with std::string_view #1") {
    REQUIRE(utils::uri_encode("https://ja.wikipedia.org/wiki/パーセントエンコーディング"sv) == 
        "https://ja.wikipedia.org/wiki/%e3%83%91%e3%83%bc%e3%82%bb%e3%83%b3%e3%83%88%e3%82%a8%e3%83%b3%e3%82%b3%e3"
        "%83%bc%e3%83%87%e3%82%a3%e3%83%b3%e3%82%b0");
}

TEST_CASE("uri_encode with std::u8string_view #2") {
    REQUIRE(utils::uri_encode(u8"https://pt.wikipedia.org/wiki/Codificação_por_cento"sv) == 
        u8"https://pt.wikipedia.org/wiki/Codifica%c3%a7%c3%a3o_por_cento");
}
TEST_CASE("uri_encode with std::string_view #2") {
    REQUIRE(utils::uri_encode("https://pt.wikipedia.org/wiki/Codificação_por_cento"sv) == 
        "https://pt.wikipedia.org/wiki/Codifica%c3%a7%c3%a3o_por_cento");
}

TEST_CASE("uri_encode with empty string") {
    CHECK(utils::uri_encode(""sv) == "");
    CHECK(utils::uri_encode(u8""sv) == u8"");
}
