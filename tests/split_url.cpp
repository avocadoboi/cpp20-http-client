#include "testing_header.hpp"

#include <iostream>

TEST_CASE("Trying split_url for https://google.com/") {
	auto const [protocol, host_name, path] = utils::split_url("https://google.com/");
	
	CHECK(protocol == Protocol::Https);
	CHECK(host_name == "google.com");
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html") {
	auto const [protocol, host_name, path] = utils::split_url("http://bjornsundin.com/projects/index.html");
	
	CHECK(protocol == Protocol::Http);
	CHECK(host_name == "bjornsundin.com");
	CHECK(path == "/projects/index.html");
}

TEST_CASE("Trying split_url for github.com/avocadoboi") {
	auto const [protocol, host_name, path] = utils::split_url("github.com/avocadoboi");
	
	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "github.com");
	CHECK(path == "/avocadoboi");
}

TEST_CASE("Trying split_url for github.com") {
	auto const [protocol, host_name, path] = utils::split_url("github.com");
	
	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "github.com");
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for single character.") {
	auto const [protocol, host_name, path] = utils::split_url("a");

	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "a");
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for empty string.") {
	auto const [protocol, host_name, path] = utils::split_url("");

	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "");
	CHECK(path == "");
}

