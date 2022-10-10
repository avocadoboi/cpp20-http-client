#include "testing_header.hpp"

TEST_CASE("Trying extract_filename with empty string") {
	CHECK(utils::extract_filename(""sv).empty());
}

TEST_CASE("Trying extract_filename with urls") {
	CHECK(utils::extract_filename("https://www.youtube.com/watch?v=lXKDu6cdXLI"sv) == "watch");
	CHECK(utils::extract_filename("http://bjornsundin.com/info/index.html"sv) == "index.html");
	CHECK(utils::extract_filename("https://github.com/avocadoboi/cpp20-http-client"sv) == "cpp20-http-client");
}

TEST_CASE("Trying extract_filename with invalid urls") {
	CHECK(utils::extract_filename("this is an invalid URL."sv).empty());
	CHECK(utils::extract_filename("öafskjahögworhwr"sv).empty());
}
