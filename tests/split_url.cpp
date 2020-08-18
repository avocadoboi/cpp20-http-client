#include <catch2/catch.hpp>

#include <cpp20_internet_client.hpp>

using namespace internet_client;
using namespace std::string_view_literals;

TEST_CASE("Trying split_url for https://google.com/") {
	auto const [host_name, path] = utils::split_url(u8"https://google.com/"sv);
	
	REQUIRE(host_name == u8"google.com");
	REQUIRE(path == u8"/");
}

TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html with utf-8") {
	auto const [host_name, path] = utils::split_url(u8"http://bjornsundin.com/projects/index.html"sv);
	
	REQUIRE(host_name == u8"bjornsundin.com");
	REQUIRE(path == u8"/projects/index.html");
}
TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html with utf-16") {
	auto const [host_name, path] = utils::split_url(u"http://bjornsundin.com/projects/index.html"sv);
	
	REQUIRE(host_name == u"bjornsundin.com");
	REQUIRE(path == u"/projects/index.html");
}
TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html with wchar_t") {
	auto const [host_name, path] = utils::split_url(L"http://bjornsundin.com/projects/index.html"sv);
	
	REQUIRE(host_name == L"bjornsundin.com");
	REQUIRE(path == L"/projects/index.html");
}

TEST_CASE("Trying split_url for github.com/avocadoboi") {
	auto const [host_name, path] = utils::split_url(u8"github.com/avocadoboi"sv);
	
	REQUIRE(host_name == u8"github.com");
	REQUIRE(path == u8"/avocadoboi");
}

TEST_CASE("Trying split_url for github.com") {
	auto const [host_name, path] = utils::split_url(u8"github.com"sv);
	
	REQUIRE(host_name == u8"github.com");
	REQUIRE(path == u8"");
}

TEST_CASE("Trying split_url for single character.") {
	auto const [host_name, path] = utils::split_url(u8"a"sv);

	REQUIRE(host_name == u8"a");
	REQUIRE(path == u8"");
}

TEST_CASE("Trying split_url for empty string.") {
	auto const [host_name, path] = utils::split_url(u8""sv);

	REQUIRE(host_name == u8"");
	REQUIRE(path == u8"");
}

TEST_CASE("Tried split_url for http://bjornsundin.com/projects/index.html at compile time.") {
	// constexpr isn't allowed for structured bindings yet :(
	constexpr auto split = utils::split_url(u8"http://bjornsundin.com/projects/index.html"sv);

	REQUIRE(split.domain_name == u8"bjornsundin.com");
	REQUIRE(split.path == u8"/projects/index.html");
}
