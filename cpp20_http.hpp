#pragma once

#include <fstream>
#include <functional>
#include <string>
#include <string_view>
#include <span>
#include <ranges>
#include <concepts>
#include <memory>
#include <algorithm>

namespace http {
	
/*
	This is everything that doesn't have anything to do with http specifically, 
	but are utilities that are used within the library.
*/
namespace util {
	
/*
	This is a concept for IsAnyOf<T, U, V, W, ...> where T is equal to any of U, V, W, ...
*/
template<typename T, typename ... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

/*
	Single parameter overload of select_on_type(...).
	It just forwards the argument to the return value.
*/
template<typename T>
[[nodiscard]]
constexpr auto select_on_type(T&& p_item) -> T&& {
	return std::forward<T>(p_item);
}
/*
	Selects a variable from the argument list based on 
	its type, which is given as a template argument.
*/
template<typename T, typename U, typename ... V> requires IsAnyOf<T, U, V...>
[[nodiscard]]
constexpr auto select_on_type(U&& p_first_item, V&& ... p_items) -> auto&&
{
	if constexpr (std::is_same_v<T, U>) {
		return std::forward<U>(p_first_item);
	}
	else {
		return select_on_type<T>(std::forward<V>(p_items)...);
	}
}

//---------------------------------------------------------

/*
	Converts a std::u8string_view to a std::string_view,
	by using the same exact bytes; there's no encoding
	conversion here. The returned std::string_view points
	to the same data, and is thus utf-8 encoded as well.
	This is only meant to be used to interoperate
	with APIs that assume regular strings to be utf-8 
	encoded.
*/
[[nodiscard]] 
inline auto u8string_to_utf8_string(std::u8string_view const p_u8string) noexcept 
	-> std::string_view 
{
	return std::string_view{
		// I think this is ok because all we're doing is telling the 
		// compiler to pretend the bytes are char instead of char8_t,
		// which is the intended behavior. The encoding should still
		// be utf-8.
		reinterpret_cast<char const*>(p_u8string.data()), 
		p_u8string.size(),
	};
}
/*
	The reverse of u8string_to_utf8_string.
*/
[[nodiscard]]
inline auto utf8_string_to_u8string(std::string_view const p_utf8_string) noexcept
	-> std::u8string_view 
{
	return std::u8string_view{
		reinterpret_cast<char8_t const*>(p_utf8_string.data()),
		p_utf8_string.size(),
	};
}

/*
	This is a concept representing any UTF-8 or UTF-16 character code point.
	It is true for char, char8_t, char16_t or wchar_t character types.
*/
template<typename T>
concept IsCharacter = IsAnyOf<T, char, char8_t, char16_t, wchar_t>;

template<
	std::ranges::view _View, 
	IsCharacter _Char = std::ranges::range_value_t<_View>,
	typename _StringView = std::basic_string_view<_Char>
>
[[nodiscard]] 
constexpr auto view_to_string_view(_View p_view) -> _StringView
{
	return {&*p_view.begin(), static_cast<_StringView::size_type>(std::ranges::distance(p_view))};
}

//---------------------------------------------------------

/*
	A safer version of std::find_if or std::ranges::find_if that 
	returns an std::optional<iterator> instead of iterator.
	It still produces the same assembly.
*/
template<
	std::ranges::range _Range, 
	typename _Iterator = std::ranges::iterator_t<_Range>,
    typename _Value = std::ranges::range_value_t<_Range>,
	std::predicate<_Value> _Predicate
>
auto find_if(
	_Range&& p_range, 
	_Predicate&& p_predicate
) -> std::optional<_Iterator>
{
	if (auto const end = p_range.end(), 
	               pos = std::ranges::find_if(std::forward<_Range>(p_range), std::forward<_Predicate>(p_predicate));
		pos == end)
	{
		return {};
	}
	else {
		return pos;
	}
}

} // namespace util

//---------------------------------------------------------

/*
	A minimal collection of internet related errors you should catch and handle yourself.
	They do not inherit from std::exception because these are made to be catched separately
	and do not have default error messages. It's your responsibility to provide useful
	error messages to the user and/or proper error handling.
*/
namespace error {

/*
	The URL or IP address was in an invalid format.
	For example, the domain part could be missing, or the
	IP address could have a number missing.
*/
struct InvalidUrl {};

/*
	The requested item was not found on the server.
*/
struct ItemNotFound {};

/*
	The connection to the server failed in some way.
	This is an enum class. To get more information about what
	type of connection error it was, check the value.
*/
enum class ConnectionFailed {
	NoInternet, // There was no internet connection
	Timeout, // The connection timed out
	Shutdown, // The connection was shut down unexpectedly
};

} // namespace error

//---------------------------------------------------------

/*
	Represents a HTTP header whose data was copied from somewhere else at some point.
	It consists of std::u8string objects instead of std::u8string_view.
*/
struct HeaderCopy {
	std::u8string name, value;
};
/*
	Represents a HTTP header whose data is not owned by this object.
	It consists of std::u8string_view objects instead of std::u8string.
*/
struct Header {
	std::u8string_view name, value;
};

/*
	Represents the response of a HTTP "GET" request.
*/
class GetResponse {
	friend class GetRequest;
	
private:
	class Implementation;
	std::unique_ptr<Implementation> m_implementation;

	GetResponse(std::unique_ptr<Implementation> p_implementation);

public:
	~GetResponse(); // = default in .cpp

	[[nodiscard]] 
	auto get_headers() const -> std::span<Header>;
	[[nodiscard]] 
	auto get_headers_string() const -> std::u8string_view;
	
	[[nodiscard]] 
	auto get_header(std::u8string_view p_header_name) const -> std::optional<Header>;
	[[nodiscard]] 
	auto get_header_value(std::u8string_view const p_header_name) const -> std::optional<std::u8string_view>;
	
	[[nodiscard]] 
	auto get_content_data() const -> std::span<std::byte>;
	[[nodiscard]] 
	auto get_content_string() const -> std::u8string_view
	{
		auto const content = get_content_data();
		return std::u8string_view{reinterpret_cast<char8_t const*>(content.data()), content.size()};
	}
	auto write_content_to_file(std::string_view p_file_name) const -> void
	{
		auto const content = get_content_data();
		auto file_stream = std::ofstream{p_file_name.data(), std::ios::binary};
		file_stream.write(reinterpret_cast<char const*>(content.data()), content.size());
	}
};

/*

*/
class GetRequest {
private:
	class Implementation;
	std::unique_ptr<Implementation> m_implementation;

public:
	~GetRequest(); // = default in .cpp

	/*
		Sets the name of the application that is sending the HTTP request.
		The default value is 
	*/
	[[nodiscard]] 
	auto set_user_agent(std::u8string_view p_user_agent) && -> GetRequest&&;

	[[nodiscard]] 
	auto add_headers(std::u8string_view p_headers) && -> GetRequest&&;
	[[nodiscard]] 
	auto add_headers(std::span<Header const> const p_headers) && -> GetRequest&& {
		auto headers_string = std::u8string{};
		headers_string.reserve(p_headers.size()*128);
		for (auto const header : p_headers) {
			// TODO: Use std::format when it has been implemented by compilers.
			(((headers_string += header.name) += u8": ") += header.value) += '\n';
		}
		return std::move(*this).add_headers(headers_string);
	}
	[[nodiscard]] 
	auto add_headers(std::initializer_list<Header const> const p_headers) && -> GetRequest&& {
		return std::move(*this).add_headers(std::span{p_headers});
	}
	[[nodiscard]] 
	auto add_header(Header p_header) && -> GetRequest&& {
		return std::move(*this).add_headers(((std::u8string{p_header.name} += u8": ") += p_header.value) += u8"\n");
	}

	[[nodiscard]] 
	auto send() && -> GetResponse;

private:
	friend auto get(std::u8string_view p_url) -> GetRequest;
	GetRequest(std::u8string_view p_url);
};

/*
	Creates a get request.
	p_url is a URL to the server or resource that the get request targets.
*/
[[nodiscard]] inline auto get(std::u8string_view p_url) -> GetRequest {
	return GetRequest{p_url};
}


//---------------------------------------------------------

/*
	These are algorithms that are used within the library.
	They are in the header because they could be useful outside it as well,
	but primarily because it makes them testable.
*/
namespace algorithms {

using namespace std::string_view_literals;

/*
	The result of the split_url function.
*/
template<util::IsCharacter _Char>
struct SplitUrl {
	std::basic_string_view<_Char> domain_name, path;
};

/*
	Splits an URL into a server/domain name and file path.
*/
template<util::IsCharacter _Char>
[[nodiscard]] 
constexpr auto split_url(std::basic_string_view<_Char> const p_url) noexcept 
	-> SplitUrl<_Char> 
{
	if (p_url.empty()) {
		return {};
	}
	
	constexpr auto forward_slash = util::select_on_type<_Char>('/', u8'/', u'/', L'/');
	constexpr auto colon = util::select_on_type<_Char>(':', u8':', u':', L':');
	
	constexpr auto minimum_split_pos = size_t{2};
	
	auto start_pos = size_t{};
	do {
		auto const pos = p_url.find(forward_slash, !start_pos ? minimum_split_pos : start_pos);
		if (pos == std::string_view::npos) {
			return {p_url.substr(start_pos), {}};
		}
		else if (auto const last = p_url[pos - 1];
			last != colon && last != forward_slash) 
		{
			return {p_url.substr(start_pos, pos - start_pos), p_url.substr(pos)};
		}
		else {
			start_pos = pos + 1;
		}
	} while (true);
}

[[nodiscard]] 
inline auto parse_headers_string(std::u8string_view const p_headers) -> std::vector<Header>
{
	auto result = std::vector<Header>();

	for (auto const line_range : std::ranges::views::split(p_headers, u8'\n')) {
		auto const line = util::view_to_string_view(line_range);

		if (auto const colon_pos = line.find(u8':');
		    colon_pos != std::u8string_view::npos)
		{
			/*
				"An HTTP header consists of its case-insensitive name followed by a colon (:), 
				then by its value. Whitespace before the value is ignored." 
				(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

				So we're just ignoring whitespace before the value, and after because there may be
				an \r there if the line endings are CRLF.
			*/
			constexpr auto whitespace_characters = u8" \t\r"sv;
			if (auto const value_start = line.find_first_not_of(whitespace_characters, colon_pos + 1);
			    value_start != std::u8string_view::npos) 
			{
				auto const value_end = line.find_last_not_of(whitespace_characters);
				result.push_back(Header{
					.name=line.substr(0, colon_pos), 
					.value=line.substr(value_start, value_end - value_start)
				});
			}
		}
	}

	return result;
}

} // namespace algorithms
} // namespace http
