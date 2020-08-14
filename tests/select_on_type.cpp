#include <catch2/catch.hpp>

#include <cpp20_http.hpp>

using namespace std::string_view_literals;

template<typename T>
constexpr auto select() {
	return http::util::select_on_type<T>('a', "hello"sv, 5, 3.14159265);
}

// This is a compile-time test, but this will ensure it'll get compiled properly because the code is used somewhere.
TEST_CASE("Tried util::select_on_type with char, std::string_view, int and double (at compile time)", "http::util::select_on_type") {
	constexpr auto a = select<char>();
	static_assert(a == 'a');
	
	constexpr auto hello = select<std::string_view>();
	static_assert(hello == "hello"sv);

	constexpr auto five = select<int>();
	static_assert(five == 5);

	constexpr auto pi = select<double>();
	static_assert(pi == 3.14159265);
}
