#include "testing_header.hpp"

#include <iostream>

TEST_CASE("Trying split_url for https://google.com/") {
	auto const [protocol, host_name, path] = utils::split_url(u8"https://google.com/"sv);
	
	CHECK(protocol == utils::Protocol::Https);
	CHECK(host_name == u8"google.com");
	CHECK(path == u8"/");
}

TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html") {
	auto const [protocol, host_name, path] = utils::split_url(u8"http://bjornsundin.com/projects/index.html"sv);
	
	CHECK(protocol == utils::Protocol::Http);
	CHECK(host_name == u8"bjornsundin.com");
	CHECK(path == u8"/projects/index.html");
}

TEST_CASE("Trying split_url for github.com/avocadoboi") {
	auto const [protocol, host_name, path] = utils::split_url(u8"github.com/avocadoboi"sv);
	
	CHECK(protocol == utils::Protocol::Unknown);
	CHECK(host_name == u8"github.com");
	CHECK(path == u8"/avocadoboi");
}

TEST_CASE("Trying split_url for github.com") {
	auto const [protocol, host_name, path] = utils::split_url(u8"github.com"sv);
	
	CHECK(protocol == utils::Protocol::Unknown);
	CHECK(host_name == u8"github.com");
	CHECK(path == u8"/");
}

TEST_CASE("Trying split_url for single character.") {
	auto const [protocol, host_name, path] = utils::split_url(u8"a"sv);

	CHECK(protocol == utils::Protocol::Unknown);
	CHECK(host_name == u8"a");
	CHECK(path == u8"/");
}

TEST_CASE("Trying split_url for empty string.") {
	auto const [protocol, host_name, path] = utils::split_url(u8""sv);

	CHECK(protocol == utils::Protocol::Unknown);
	CHECK(host_name == u8"");
	CHECK(path == u8"");
}

