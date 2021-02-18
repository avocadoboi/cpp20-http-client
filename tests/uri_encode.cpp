#include "testing_header.hpp"

TEST_CASE("uri_encode #1") {
    REQUIRE(utils::uri_encode("https://ja.wikipedia.org/wiki/パーセントエンコーディング"sv) == 
        "https://ja.wikipedia.org/wiki/%e3%83%91%e3%83%bc%e3%82%bb%e3%83%b3%e3%83%88%e3%82%a8%e3%83%b3%e3%82%b3%e3"
        "%83%bc%e3%83%87%e3%82%a3%e3%83%b3%e3%82%b0");
}

TEST_CASE("uri_encode #2") {
    REQUIRE(utils::uri_encode("https://pt.wikipedia.org/wiki/Codificação_por_cento"sv) == 
        "https://pt.wikipedia.org/wiki/Codifica%c3%a7%c3%a3o_por_cento");
}

TEST_CASE("uri_encode with already encoded std::string_view") {
    auto const url = "https://ja.wikipedia.org/wiki/%E3%83%A1%E3%82%A4%E3%83%B3%E3%83%9A%E3%83%BC%E3%82%B8"sv;
    REQUIRE(utils::uri_encode(url) == url);
}

TEST_CASE("uri_encode with empty string") {
    CHECK(utils::uri_encode(""sv) == "");
}
