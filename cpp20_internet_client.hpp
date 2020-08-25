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
[[nodiscard]] constexpr auto select_on_type(T&& item) noexcept -> T&& {
	return std::forward<T>(item);
}
/*
	Selects a variable from the argument list based on 
	its type, which is given as a template argument.
*/
template<typename T, typename U, typename ... V> requires IsAnyOf<T, U, V...>
[[nodiscard]] constexpr auto select_on_type(U&& first_item, V&& ... items) noexcept -> auto&& {
	if constexpr (std::is_same_v<T, U>) {
		return std::forward<U>(first_item);
	}
	else {
		return select_on_type<T>(std::forward<V>(items)...);
	}
}

//---------------------------------------------------------

template<typename T> requires requires (T callable) { callable(); }
class Cleanup {
private:
	T m_callable;
	
public:
	Cleanup(T&& callable) :
		m_callable{std::forward<T>(callable)}
	{}
	~Cleanup() {
		m_callable();
	}

	Cleanup(Cleanup const&) = delete;
	auto operator=(Cleanup const&) -> Cleanup& = delete;
	Cleanup(Cleanup&&) = delete;
	auto operator=(Cleanup&&) -> Cleanup& = delete;
};

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
inline auto u8string_to_utf8_string(std::u8string_view const u8string) noexcept 
	-> std::string_view 
{
	return std::string_view{
		// I think this is ok because all we're doing is telling the 
		// compiler to pretend the bytes are char instead of char8_t,
		// which is the intended behavior. The encoding should still
		// be utf-8.
		reinterpret_cast<char const*>(u8string.data()), // TODO: replace with bit_cast when compilers have implemented it.
		u8string.size(),
	};
}
/*
	The reverse of u8string_to_utf8_string.
*/
[[nodiscard]]
inline auto utf8_string_to_u8string(std::string_view const utf8_string) noexcept
	-> std::u8string_view 
{
	return std::u8string_view{
		reinterpret_cast<char8_t const*>(utf8_string.data()),
		utf8_string.size(),
	};
}

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
	IsAnyOf<char8_t, char> _Char = std::ranges::range_value_t<_Range>
> 
[[nodiscard]] 
constexpr auto range_to_string_view(_Range const& range) -> std::basic_string_view<_Char>
{
	return {&*range.begin(), static_cast<std::string_view::size_type>(std::ranges::distance(range))};
}

//---------------------------------------------------------

auto enable_utf8_console() -> void;

//---------------------------------------------------------

/*
	Copies a sized range to a std::basic_string of any type.
*/
template<
	std::ranges::sized_range _Range,
	IsAnyOf<char8_t, char> _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string<_Char>
> 
[[nodiscard]]
inline auto range_to_string(_Range const& range) -> _String {
	auto result = _String(range.size(), static_cast<_Char>(0));
	std::ranges::copy(range, result.begin());
	return result;
}

/*
	Copies a range of unknown size to a std::basic_string of any type.
*/
template<
	std::ranges::range _Range,
	IsAnyOf<char8_t, char> _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string_view<_Char>
> 
[[nodiscard]]
inline auto range_to_string(_Range const& range) -> _String {
	auto result = _String();
	std::ranges::copy(range, std::back_inserter(result));
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
	_Range&& range, 
	_Predicate&& predicate
) noexcept -> std::optional<_Iterator>
{
	if (auto const end = range.end(), 
	               pos = std::ranges::find_if(std::forward<_Range>(range), std::forward<_Predicate>(predicate));
		pos == end)
	{
		return {};
	}
	else {
		return pos;
	}
}

constexpr auto ascii_lowercase_transform = std::views::transform([](char c) { return static_cast<char>(std::tolower(c)); });

constexpr auto equal_ascii_case_insensitive(
	std::string_view const lhs, std::string_view const rhs
) noexcept -> bool 
{
	return std::ranges::equal(lhs | ascii_lowercase_transform, rhs | ascii_lowercase_transform);
}

//---------------------------------------------------------

using Port = int;

enum class Protocol : Port {
	Http = 80,
	Https = 443,
	Ftp = 21,
	Sftp = 22,
	Unknown = -1, 
};

constexpr auto get_port(Protocol protocol) noexcept -> Port {
	return static_cast<Port>(protocol);
}

inline auto get_protocol_from_string(std::u8string_view const protocol_string) noexcept -> Protocol 
{
	if (auto const ascii_string = u8string_to_utf8_string(protocol_string);
		equal_ascii_case_insensitive(ascii_string, "http")) 
	{
		return Protocol::Http;
	}
	else if (equal_ascii_case_insensitive(ascii_string, "https")) {
		return Protocol::Https;
	}
	else if (equal_ascii_case_insensitive(ascii_string, "ftp")) {
		return Protocol::Ftp;
	}
	else if (equal_ascii_case_insensitive(ascii_string, "sftp")) {
		return Protocol::Sftp;
	}
	return Protocol::Unknown;
}

/*
	The result of the split_url function.
*/
struct SplitUrl {
	Protocol protocol{Protocol::Unknown};
	std::u8string_view domain_name, path;
};

/*
	Splits an URL into a server/domain name and file path.
*/
[[nodiscard]] 
inline auto split_url(std::u8string_view const url) noexcept -> SplitUrl 
{
	if (url.empty()) {
		return {};
	}
	
	constexpr auto whitespace_characters = std::u8string_view{u8" \t\r\n"};
	auto start_position = url.find_first_not_of(whitespace_characters);
	if (start_position == std::u8string_view::npos) {
		return {};
	}
	
	auto result = SplitUrl{};

	constexpr auto protocol_suffix = std::u8string_view{u8"://"};
	if (auto const position = url.find(protocol_suffix, start_position);
		position != std::u8string_view::npos) 
	{
		result.protocol = get_protocol_from_string(url.substr(start_position, position - start_position));
		start_position = position + protocol_suffix.length();
	}

	if (auto const position = url.find(u8'/', start_position);
		position != std::u8string_view::npos)
	{
		result.domain_name = url.substr(start_position, position - start_position);
		start_position = position;
	}
	else {
		result.domain_name = url.substr(start_position);
		return result;
	}

	auto const end_position = url.find_last_not_of(whitespace_characters) + 1;
	result.path = url.substr(start_position, end_position - start_position);
	return result;
}

/*
	Returns the file name part of a URL (or file path with only forward slashes).
*/
constexpr auto extract_filename(std::u8string_view const url) noexcept -> std::u8string_view
{
	if (auto const slash_pos = url.rfind(u8'/');
		slash_pos != std::u8string_view::npos)
	{
		if (auto const question_mark_pos = url.find(u8'?', slash_pos + 1);
			question_mark_pos != std::u8string_view::npos)
		{
			return url.substr(slash_pos + 1, question_mark_pos - slash_pos - 1);
		}

		return url.substr(slash_pos + 1);
	}
	return {};
}

constexpr auto get_is_allowed_uri_character(char const character) noexcept -> bool {
	constexpr auto other_characters = std::string_view{"-._~:/?#[]@!$&'()*+,;="};
	
	return character >= '0' && character <= '9' || 
		character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		other_characters.find(character) != std::string_view::npos;
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
	The connection to the server failed in some way.
	For example, there is no internet connection or the server name is invalid.
*/
struct ConnectionFailed {};

} // namespace errors

//---------------------------------------------------------

struct SocketResponse {
	std::vector<std::byte> data;

	template<utils::IsAnyOf<char, char8_t> T = char8_t>
	auto as_string() const -> std::basic_string_view<T> {
		return {reinterpret_cast<T const*>(data.data()), data.size()};
	}
};

class Socket {
public:
	[[nodiscard]]
	auto send(std::span<std::byte const> data) const -> SocketResponse;
	[[nodiscard]]
	auto send(std::u8string_view string) const -> SocketResponse {
		return send(std::span{reinterpret_cast<std::byte const*>(string.data()), string.length()});
	}
	[[nodiscard]]
	auto send(std::string_view string) const -> SocketResponse {
		return send(std::span{reinterpret_cast<std::byte const*>(string.data()), string.length()});
	}

	Socket(); // = default in .cpp
	Socket(Socket&&); // = default in .cpp
	auto operator=(Socket&&) -> Socket&; // = default in .cpp
	Socket(Socket const&) = delete;
	auto operator=(Socket const&) -> Socket& = delete;

	~Socket(); // = default in .cpp

private:
	class Implementation;
	std::unique_ptr<Implementation> m_implementation;
	
	Socket(std::u8string_view server, utils::Port port);
	friend auto open_socket(std::u8string_view server, utils::Port port) -> Socket;
};

inline auto open_socket(std::u8string_view const server, utils::Port const port) -> Socket {
	return Socket{server, port};
}

//---------------------------------------------------------

namespace http {

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

namespace algorithms {

[[nodiscard]] 
inline auto parse_headers_string(std::string_view const headers) -> std::vector<Header>
{
	auto result = std::vector<Header>();

	for (auto const line_range : std::views::split(headers, '\n')) {
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
			constexpr auto whitespace_characters = std::string_view{" \t\r"};
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

//---------------------------------------------------------

/*
	Represents the response of a HTTP "GET" request.
*/
class GetResponse {
	friend class GetRequest;

private:
	Socket m_socket;

	std::optional<std::string> m_headers_string;
	auto query_headers_string() const -> void {
	}

public:
	/*
		Returns the headers of the GET response as a string.
		The returned string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers_string() const -> std::string_view {
		if (!m_headers_string) {
			query_headers_string();
		}
		return *m_headers_string;
	}

private:
	std::optional<std::vector<Header>> mutable m_parsed_headers;

	auto parse_headers() const -> void {
		if (!m_headers_string) {
			query_headers_string();
		}
		m_parsed_headers = algorithms::parse_headers_string(*m_headers_string);
	}

	[[nodiscard]]
	auto find_header(std::string_view const name_to_find) const
		-> std::optional<std::vector<Header>::iterator>
	{
		if (!m_parsed_headers) {
			parse_headers();
		}

		auto const lowercase_name_to_search = utils::range_to_string(name_to_find | utils::ascii_lowercase_transform);
		return utils::find_if(*m_parsed_headers, [&](auto const& header) {
			return std::ranges::equal(lowercase_name_to_search, header.name | utils::ascii_lowercase_transform);
		});
	}

public:
	/*
		Returns the headers of the GET response as Header objects.
		The returned span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers() const -> std::span<Header> {
		if (!m_parsed_headers) {
			parse_headers();
		}
		return *m_parsed_headers;
	}
	/*
		Returns a header of the GET response by its name.
		The returned header shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/	
	[[nodiscard]] 
	auto get_header(std::string_view const name) const -> std::optional<Header> {
		if (auto const pos = find_header(name)) {
			return **pos;
		}
		else {
			return {};
		}
	}
	/*
		Returns a header value of the GET response by its name.
		The returned std::string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_header_value(std::string_view const name) const -> std::optional<std::string_view> {
		if (auto const pos = find_header(name)) {
			return (*pos)->value;
		}
		else {
			return {};
		}
	}
	
private:
	std::optional<std::vector<std::byte>> mutable m_body;
	auto read_response_body() const -> void {
	}
public:
	/*
		Returns the body of the GET response.
		The returned std::span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]]
	auto get_body() const -> std::span<std::byte> {
		if (!m_body) {
			read_response_body();
		}
		return *m_body;
	}
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

	GetResponse() = delete;
	~GetResponse() = default;
	
	GetResponse(GetResponse&&) = default;
	auto operator=(GetResponse&&) -> GetResponse& = default;

	GetResponse(GetResponse const&) = delete;
	auto operator=(GetResponse const&) -> GetResponse& = delete;

private:
	GetResponse(Socket&& socket) :
		m_socket{std::move(socket)}
	{}
};

//---------------------------------------------------------

/*
	Represents a "GET" request.
	It is created by calling the http::get function.
*/
class GetRequest {
private:
	std::string m_user_agent = std::string{GetRequest::default_user_agent};

public:
	static constexpr auto default_user_agent = std::string_view{"Cpp20InternetClient"};

	/*
		Sets the name of the application that is sending the HTTP request.
		The default value is GetRequest::default_user_agent.
	*/
	auto set_user_agent(std::string_view const user_agent) && -> GetRequest&& {
		m_user_agent = user_agent;
		return std::move(*this);
	}

private:
	std::string m_headers;
public:
	/*
		Adds headers to the GET request as a string.
		These are in the format: "NAME: [ignored whitespace] VALUE"
		The string can be multiple lines for multiple headers.
		Non-ASCII bytes are considered opaque data,
		according to the HTTP specification.
	*/
	auto add_headers(std::string_view const headers_string) && -> GetRequest&& {
		if (headers_string.empty()) {
			return std::move(*this);
		}
		m_headers += headers_string;
		if (headers_string.back() != '\n') {
			m_headers += "\r\n"; // CRLF is the correct line ending for the HTTP protocol
		}
		return std::move(*this);
	}
	/*
		Adds headers to the GET request.
	*/
	auto add_headers(std::span<Header const> const headers) && -> GetRequest&& {
		auto headers_string = std::string{};
		headers_string.reserve(headers.size()*128);
		for (auto const header : headers) {
			// TODO: Use std::format when it has been implemented by compilers.
			(((headers_string += header.name) += ": ") += header.value) += "\r\n";
		}
		return std::move(*this).add_headers(headers_string);
	}
	/*
		Adds headers to the GET request.
	*/
	auto add_headers(std::initializer_list<Header const> const headers) && -> GetRequest&& {
		return std::move(*this).add_headers(std::span{headers});
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
	auto add_header(Header header) && -> GetRequest&& {
		return std::move(*this).add_headers(((std::string{header.name} += ": ") += header.value));
	}

private:
	utils::SplitUrl m_split_url;
	Socket m_socket;

public:
	/*
		Sends the GET request.
	*/
	[[nodiscard]] 
	auto send() && -> GetResponse {
		return GetResponse{std::move(m_socket)};
	}

	GetRequest() = delete;

	GetRequest(GetRequest&&) = default;
	auto operator=(GetRequest&&) -> GetRequest& = default;
	GetRequest(GetRequest const&) = delete;
	auto operator=(GetRequest const&) -> GetRequest& = delete;

	~GetRequest() = default;

private:
	friend auto get(std::u8string_view url) -> GetRequest;
	GetRequest(std::u8string_view url) :
		m_split_url{utils::split_url(url)},
		m_socket{open_socket(m_split_url.domain_name, utils::get_port(m_split_url.protocol))}
	{}
};

/*
	Creates a GET request.
	url is a URL to the server or resource that the GET request targets.
*/
[[nodiscard]] 
inline auto get(std::u8string_view const url) -> GetRequest {
	return GetRequest{url};
}
/*
	Creates a GET request.
	url is a URL to the server or resource that the GET request targets.
*/
[[nodiscard]] 
inline auto get(std::string_view const url) -> GetRequest {
	return get(utils::utf8_string_to_u8string(url));
}

} // namespace http

namespace ftp {
	
} // namespace ftp

} // namespace internet_client
