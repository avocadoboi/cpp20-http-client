#include <catch2/catch.hpp>

#include <cpp20_internet_client.hpp>

using namespace internet_client;
using namespace std::string_view_literals;

TEST_CASE("Trying extract_filename with empty string") {
	REQUIRE(utils::extract_filename(""sv).empty());
}

TEST_CASE("Trying extract_filename with urls") {
	CHECK(utils::extract_filename("https://www.youtube.com/watch?v=lXKDu6cdXLI"sv) == "watch");
	CHECK(utils::extract_filename("http://bjornsundin.com/info/index.html"sv) == "index.html");
	CHECK(utils::extract_filename("https://github.com/avocadoboi/cpp20-internet-client"sv) == "cpp20-internet-client");
}

TEST_CASE("Trying extract_filename with different encodings") {
	CHECK(utils::extract_filename(u8"https://github.com/avocadoboi/cpp20-internet-client"sv) == u8"cpp20-internet-client");
	CHECK(utils::extract_filename(u"https://github.com/avocadoboi/cpp20-internet-client"sv) == u"cpp20-internet-client");
	CHECK(utils::extract_filename(U"https://github.com/avocadoboi/cpp20-internet-client"sv) == U"cpp20-internet-client");
	CHECK(utils::extract_filename(L"https://github.com/avocadoboi/cpp20-internet-client"sv) == L"cpp20-internet-client");
}

TEST_CASE("Trying extract_filename with invalid urls") {
	CHECK(utils::extract_filename("this is an invalid URL."sv).empty());
	CHECK(utils::extract_filename(u8"öafskjahögworhwr"sv).empty());
}
