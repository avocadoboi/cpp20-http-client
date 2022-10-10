#include "testing_header.hpp"

void check_status_line(StatusLine const& status_line) {
    CHECK(status_line.http_version == "HTTP/1.1");
    CHECK(status_line.status_code == StatusCode::Forbidden);
    CHECK(status_line.status_message == "Forbidden");
}

TEST_CASE("parse_status_line without newline") {
    auto const status_line = algorithms::parse_status_line("HTTP/1.1 403 Forbidden");
    check_status_line(status_line);
}
TEST_CASE("parse_status_line with newline") {
    auto const status_line = algorithms::parse_status_line("HTTP/1.1 403 Forbidden\r\n");
    check_status_line(status_line);
}
TEST_CASE("parse_status_line with nonconforming newline") {
    auto const status_line = algorithms::parse_status_line("HTTP/1.1 403 Forbidden\n");
    check_status_line(status_line);
}
TEST_CASE("parse_status_line with empty string") {
    auto const [http_version, status_code, status_message] = algorithms::parse_status_line("");
    CHECK(http_version.empty());
    CHECK(status_code == StatusCode::Unknown);
    CHECK(status_message.empty()); 
}
