#include "testing_header.hpp"

#include <iostream>

TEST_CASE("Trying split_url for a localhost address") {
	auto const [protocol, host_name, port, path] = utils::split_url("http://localhost:8082/blablabla");

	CHECK(protocol == Protocol::Http);
	CHECK(host_name == "localhost");
	CHECK(port == Port{8082});
	CHECK(path == "/blablabla");
}
TEST_CASE("Trying split_url for a localhost address without path") {
	auto const [protocol, host_name, port, path] = utils::split_url("https://localhost:8082");

	CHECK(protocol == Protocol::Https);
	CHECK(host_name == "localhost");
	CHECK(port == Port{8082});
	CHECK(path == "/");
}
TEST_CASE("Trying split_url for a localhost address with invalid port number") {
	auto const [protocol, host_name, port, path] = utils::split_url("https://localhost:what/blablabla");

	CHECK(protocol == Protocol::Https);
	CHECK(host_name == "localhost");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/blablabla");
}

TEST_CASE("Trying split_url for https://google.com/") {
	auto const [protocol, host_name, port, path] = utils::split_url("https://google.com/");
	
	CHECK(protocol == Protocol::Https);
	CHECK(host_name == "google.com");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/");
}
TEST_CASE("Trying split_url for https://google.com/ with extra spacing") {
	auto const [protocol, host_name, port, path] = utils::split_url("  	\thttps://google.com/ \n ");
	
	CHECK(protocol == Protocol::Https);
	CHECK(host_name == "google.com");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for http://bjornsundin.com/projects/index.html") {
	auto const [protocol, host_name, port, path] = utils::split_url("http://bjornsundin.com/projects/index.html");
	
	CHECK(protocol == Protocol::Http);
	CHECK(host_name == "bjornsundin.com");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/projects/index.html");
}

TEST_CASE("Trying split_url for github.com/avocadoboi") {
	auto const [protocol, host_name, port, path] = utils::split_url("github.com/avocadoboi");
	
	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "github.com");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/avocadoboi");
}

TEST_CASE("Trying split_url for github.com") {
	auto const [protocol, host_name, port, path] = utils::split_url("github.com");
	
	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "github.com");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for single character.") {
	auto const [protocol, host_name, port, path] = utils::split_url("a");

	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "a");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "/");
}

TEST_CASE("Trying split_url for empty string.") {
	auto const [protocol, host_name, port, path] = utils::split_url("");

	CHECK(protocol == Protocol::Unknown);
	CHECK(host_name == "");
	CHECK(port == utils::default_port_for_protocol(protocol));
	CHECK(path == "");
}

