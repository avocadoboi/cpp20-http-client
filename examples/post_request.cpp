#include <cpp20_http_client.hpp>

using namespace http_client;

int main() {
    auto const response = post("https://postman-echo.com/post?one=A&two=B")
        .add_header({.name="Content-Type", .value="application/json"})
        .set_body(R"({"numbers": [1, 2, 3, 4, 5]})")
        .send();
    std::cout << "Response: \n" << response.get_body_string() << '\n';
}
