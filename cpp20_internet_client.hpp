/*
MIT License

Copyright (c) 2020 Björn Sundin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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

// Debugging
// #include <iostream>

/*
Namespaces:

internet_client {
	utils
	errors
	http {
		algorithms
	}
	ftp
}
*/

namespace internet_client {

/*
	This is everything that doesn't have anything to do with http or ftp specifically, 
	but are utilities that are used within the library.
*/
namespace utils {
	
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
constexpr auto select_on_type(T&& p_item) noexcept -> T&& {
	return std::forward<T>(p_item);
}
/*
	Selects a variable from the argument list based on 
	its type, which is given as a template argument.
*/
template<typename T, typename U, typename ... V> requires IsAnyOf<T, U, V...>
[[nodiscard]]
constexpr auto select_on_type(U&& p_first_item, V&& ... p_items) noexcept -> auto&& {
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

/*
	Converts a range of contiguous characters to a std::basic_string_view.
*/
template<
	/* 
		std::views::split returns a range of ranges.
		The ranges unfortunately are not std::ranges::contiguous_range
		even when the base type is contiguous, so we can't use that constraint.
	*/
	std::ranges::range _Range,
	IsCharacter _Char = std::ranges::range_value_t<_Range>,
	typename _StringView = std::basic_string_view<_Char>
>
[[nodiscard]] 
constexpr auto range_to_string_view(_Range const& p_range) -> _StringView
{
	return {&*p_range.begin(), static_cast<_StringView::size_type>(std::ranges::distance(p_range))};
}

//---------------------------------------------------------

/*
	Copies a sized range to a std::basic_string of any type.
*/
template<
	std::ranges::sized_range _Range, 
	IsCharacter _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string<_Char>
>
[[nodiscard]]
inline auto range_to_string(_Range const& p_range) -> _String {
	auto result = _String(p_range.size(), static_cast<_Char>(0));
	std::ranges::copy(p_range, result.begin());
	return result;
}

/*
	Copies a range of unknown size to a std::basic_string of any type.
*/
template<
	std::ranges::range _Range, 
	IsCharacter _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string<_Char>
>
[[nodiscard]]
inline auto range_to_string(_Range const& p_range) -> _String {
	auto result = _String{};
	std::ranges::copy(p_range, std::back_inserter(result));
	return result;
}

//---------------------------------------------------------

/*
	A version of std::find_if or std::ranges::find_if that 
	returns an std::optional<iterator> instead of iterator
	and thus it's harder to dereference the end iterator.
	It still produces the same assembly.
*/
template<
	std::ranges::range _Range, 
	typename _Iterator = std::ranges::iterator_t<_Range>,
    typename _Value = std::ranges::range_value_t<_Range>,
	std::predicate<_Value> _Predicate
>
[[nodiscard]]
constexpr auto find_if(
	_Range&& p_range, 
	_Predicate&& p_predicate
) noexcept -> std::optional<_Iterator>
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

constexpr auto ascii_lowercase_transform = std::views::transform([](char c) { return static_cast<char>(std::tolower(c)); });

//---------------------------------------------------------

/*
	The result of the split_url function.
*/
template<utils::IsCharacter _Char>
struct SplitUrl {
	std::basic_string_view<_Char> domain_name, path;
};

template<utils::IsCharacter _Char>
constexpr auto forward_slash = utils::select_on_type<_Char>('/', u8'/', u'/', L'/');

/*
	Splits an URL into a server/domain name and file path.
*/
template<IsCharacter _Char>
[[nodiscard]] 
constexpr auto split_url(std::basic_string_view<_Char> const p_url) noexcept 
	-> SplitUrl<_Char> 
{
	if (p_url.empty()) {
		return {};
	}
	
	constexpr auto colon = select_on_type<_Char>(':', u8':', u':', L':');
	
	constexpr auto minimum_split_pos = size_t{2};
	
	auto start_pos = size_t{};
	do {
		if (auto const pos = p_url.find(forward_slash<_Char>, start_pos ? start_pos : minimum_split_pos);
			pos == std::string_view::npos) 
		{
			return {p_url.substr(start_pos), {}};
		}
		else if (auto const last = p_url[pos - 1];
			last != colon && last != forward_slash<_Char>) 
		{
			return {p_url.substr(start_pos, pos - start_pos), p_url.substr(pos)};
		}
		else {
			start_pos = pos + 1;
		}
	} while (true);
}

/*
*/
template<IsCharacter _Char>
constexpr auto extract_filename(std::basic_string_view<_Char> const p_url) noexcept
	-> std::basic_string_view<_Char>
{
	if (auto const slash_pos = p_url.rfind(forward_slash<_Char>);
		slash_pos != std::string_view::npos)
	{
		constexpr auto question_mark = select_on_type<_Char>('?', u8'?', u'?', L'?');

		if (auto const question_mark_pos = p_url.find(question_mark, slash_pos + 1);
			question_mark_pos != std::string_view::npos)
		{
			return p_url.substr(slash_pos + 1, question_mark_pos - slash_pos - 1);
		}

		return p_url.substr(slash_pos + 1);
	}
	return {};
}

} // namespace utils

//---------------------------------------------------------

/*
	A minimal collection of internet related errors you should catch and handle yourself.
	They do not inherit from std::exception because these are made to be catched separately
	and do not have default error messages. It's your responsibility to provide useful
	error messages to the user and/or proper error handling.
*/
namespace errors {

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

} // namespace errors

//---------------------------------------------------------

namespace http {

using namespace std::string_view_literals;

//---------------------------------------------------------

struct Header;

/*
	Represents a HTTP header whose data was copied from somewhere else at some point.
	It consists of std::string objects instead of std::string_view.
*/
struct HeaderCopy {
	std::string name, value;

	inline explicit operator Header();
};
/*
	Represents a HTTP header whose data is not owned by this object.
	It consists of std::string_view objects instead of std::string.
*/
struct Header {
	std::string_view name, value;

	explicit operator HeaderCopy()
	{
		return HeaderCopy{
			.name = std::string{name},
			.value = std::string{value},
		};
	}
};
HeaderCopy::operator Header()
{
	return Header{
		.name = std::string_view{name},
		.value = std::string_view{value},
	};
}

template<typename T>
concept IsHeader = utils::IsAnyOf<T, HeaderCopy, Header>;

/*
	Compares two headers, taking into account case insensitivity.
*/
auto operator==(IsHeader auto const& lhs, IsHeader auto const& rhs) -> bool {
	return std::ranges::equal(
		lhs.name | utils::ascii_lowercase_transform, 
		rhs.name | utils::ascii_lowercase_transform
	) && lhs.value == rhs.value;
}

//---------------------------------------------------------

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
	GetResponse(GetResponse&&); // = default in .cpp
	auto operator=(GetResponse&&) -> GetResponse&; // = default in .cpp
	GetResponse(GetResponse const&) = delete;
	auto operator=(GetResponse const&) -> GetResponse& = delete;

	~GetResponse(); // = default in .cpp

	/*
		Returns the headers of the GET response as Header objects.
		The returned span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers() const -> std::span<Header>;
	/*
		Returns the headers of the GET response as a string.
		The returned string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers_string() const -> std::string_view;

	/*
		Returns a header of the GET response by its name.
		The returned header shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/	
	[[nodiscard]] 
	auto get_header(std::string_view header_name) const -> std::optional<Header>;
	/*
		Returns a header value of the GET response by its name.
		The returned std::string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_header_value(std::string_view header_name) const -> std::optional<std::string_view>;
	
	/*
		Returns the body of the GET response.
		The returned std::span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_body() const -> std::span<std::byte>;
	/*
		Returns the body of the GET response as a string.
		The returned std::u8string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_body_string() const -> std::u8string_view
	{
		auto const body = get_body();
		return std::u8string_view{reinterpret_cast<char8_t const*>(body.data()), body.size()};
	}

	//TODO: support unicode file names by creating our own simple file I/O API. The standard library sucks at unicode.
	
	/*
		Writes the body of the GET response to a file with the name file_name.
	*/
	auto write_body_to_file(std::string const& file_name) const -> void 
	{
		// std::string because std::ofstream does not take std::string_view.
		auto const body = get_body();
		auto file_stream = std::ofstream{file_name, std::ios::binary};
		file_stream.write(reinterpret_cast<char const*>(body.data()), body.size());
	}
};

//---------------------------------------------------------

/*
	Represents a "GET" request.
	It is created by calling the http::get function.
*/
class GetRequest {
private:
	class Implementation;
	std::unique_ptr<Implementation> m_implementation;

public:
	GetRequest(GetRequest&&); // = default in .cpp
	auto operator=(GetRequest&&) -> GetRequest&; // = default in .cpp
	GetRequest(GetRequest const&) = delete;
	auto operator=(GetRequest const&) -> GetRequest& = delete;

	~GetRequest(); // = default in .cpp

	static constexpr auto default_user_agent = "Cpp20InternetClient"sv;

	/*
		Sets the name of the application that is sending the HTTP request.
		The default value is GetRequest::default_user_agent.
	*/
	auto set_user_agent(std::string_view p_user_agent) && -> GetRequest&&;

	/*
		Adds headers to the GET request as a string.
		These are in the format: "NAME: [ignored whitespace] VALUE"
		The string can be multiple lines for multiple headers.
		Non-ASCII bytes are considered opaque data,
		according to the HTTP specification.
	*/
	auto add_headers(std::string_view p_headers) && -> GetRequest&&;
	/*
		Adds headers to the GET request.
	*/
	auto add_headers(std::span<Header const> const p_headers) && -> GetRequest&& {
		auto headers_string = std::string{};
		headers_string.reserve(p_headers.size()*128);
		for (auto const header : p_headers) {
			// TODO: Use std::format when it has been implemented by compilers.
			(((headers_string += header.name) += ": ") += header.value) += "\r\n";
		}
		return std::move(*this).add_headers(headers_string);
	}
	/*
		Adds headers to the GET request.
	*/
	auto add_headers(std::initializer_list<Header const> const p_headers) && -> GetRequest&& {
		return std::move(*this).add_headers(std::span{p_headers});
	}
	/*
		Adds headers to the GET request.
		This is a variadic template that can take any number of headers.
	*/
	template<IsHeader ... T>
	auto add_headers(T&& ... p_headers) && -> GetRequest&& {
		auto const headers = std::array{Header{p_headers}...};
		return std::move(*this).add_headers(std::span{headers});
	}
	/*
		Adds a single header to the GET request.
		Equivalent to add_headers with a single Header argument.
	*/
	auto add_header(Header p_header) && -> GetRequest&& {
		return std::move(*this).add_headers(((std::string{p_header.name} += ": ") += p_header.value));
	}

	/*
		Sends the GET request.
	*/
	[[nodiscard]] 
	auto send() && -> GetResponse;

private:
	friend auto get(std::u8string_view p_url) -> GetRequest;
	GetRequest(std::u8string_view p_url);
};

/*
	Creates a GET request.
	p_url is a URL to the server or resource that the GET request targets.
*/
[[nodiscard]] 
inline auto get(std::u8string_view const p_url) -> GetRequest {
	return GetRequest{p_url};
}
/*
	Creates a GET request.
	p_url is a URL to the server or resource that the GET request targets.
*/
[[nodiscard]] 
inline auto get(std::string_view const p_url) -> GetRequest {
	return get(utils::utf8_string_to_u8string(p_url));
}

//---------------------------------------------------------

/*
	These are algorithms that are used within the HTTP library.
*/
namespace algorithms {

[[nodiscard]] 
inline auto parse_headers_string(std::string_view const p_headers) -> std::vector<Header>
{
	auto result = std::vector<Header>();

	for (auto const line_range : std::views::split(p_headers, '\n')) {
		auto const line = utils::range_to_string_view(line_range);

		if (auto const colon_pos = line.find(':');
		    colon_pos != std::u8string_view::npos)
		{
			/*
				"An HTTP header consists of its case-insensitive name followed by a colon (:), 
				then by its value. Whitespace before the value is ignored." 
				(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

				So we're just ignoring whitespace before the value, and after because there may be
				an \r there if the line endings are CRLF.
			*/
			constexpr auto whitespace_characters = " \t\r"sv;
			if (auto const value_start = line.find_first_not_of(whitespace_characters, colon_pos + 1);
			    value_start != std::string_view::npos) 
			{
				auto const value_end = line.find_last_not_of(whitespace_characters);
				result.push_back(Header{
					.name=line.substr(0, colon_pos), 
					.value=line.substr(value_start, value_end + 1 - value_start)
				});
			}
		}
	}

	return result;
}

} // namespace algorithms

} // namespace http

namespace ftp {
	
} // namespace ftp

} // namespace internet_client
