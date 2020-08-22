#include <catch2/catch.hpp>

#include <cpp20_internet_client.hpp>

using namespace internet_client;
using namespace std::string_view_literals;

TEST_CASE("Trying extract_filename with empty string") {
	REQUIRE(utils::extract_filename(u8""sv).empty());
}

TEST_CASE("Trying extract_filename with urls") {
	CHECK(utils::extract_filename(u8"https://www.youtube.com/watch?v=lXKDu6cdXLI"sv) == u8"watch");
	CHECK(utils::extract_filename(u8"http://bjornsundin.com/info/index.html"sv) == u8"index.html");
	CHECK(utils::extract_filename(u8"https://github.com/avocadoboi/cpp20-internet-client"sv) == u8"cpp20-internet-client");
}

TEST_CASE("Trying extract_filename with invalid urls") {
	CHECK(utils::extract_filename(u8"this is an invalid URL."sv).empty());
	CHECK(utils::extract_filename(u8"öafskjahögworhwr"sv).empty());
}
