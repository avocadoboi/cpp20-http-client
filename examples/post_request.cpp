#include <cpp20_internet_client.hpp>

using namespace internet_client;

auto main() -> int {
    auto const response = http::post("https://postman-echo.com/post?one=A&two=B").send();
    std::cout << "Response: \n" << response.get_body_string<char>() << '\n';
}
