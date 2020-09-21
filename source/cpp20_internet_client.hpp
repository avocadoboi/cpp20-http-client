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
#include <thread>
#include <variant>
#include <charconv>

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
}
*/

namespace internet_client {

/*
	This is everything that doesn't have anything to do with http specifically, 
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
constexpr auto select_on_type(T&& item) noexcept -> T&& {
	return std::forward<T>(item);
}
/*
	Selects a variable from the argument list based on 
	its type, which is given as a template argument.
*/
template<typename T, typename U, typename ... V> requires IsAnyOf<T, U, V...>
[[nodiscard]] 
constexpr auto select_on_type(U&& first_item, V&& ... items) noexcept -> auto&& {
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

	Cleanup() = delete;
	~Cleanup() {
		m_callable();
	}

	Cleanup(Cleanup&&) = delete;
	auto operator=(Cleanup&&) -> Cleanup& = delete;

	Cleanup(Cleanup const&) = delete;
	auto operator=(Cleanup const&) -> Cleanup& = delete;
};

//---------------------------------------------------------

template<typename T>
concept IsByte = sizeof(T) == 1 && std::is_trivial_v<T>;

template<typename T>
concept IsByteChar = IsAnyOf<T, char, char8_t>;

template<typename T>
concept IsByteStringView = IsAnyOf<T, std::string_view, std::u8string_view>;

//---------------------------------------------------------

/*
	Creates T with the same constness as U.
*/
template<typename T, typename U>
using MatchConst = std::conditional_t<std::same_as<U, U const>, T const, std::remove_const_t<T>>;

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
	return {
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
	return {
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
constexpr auto range_to_string_view(_Range const& range) 
	-> std::basic_string_view<_Char>
{
	return {
		&*range.begin(), 
		static_cast<std::string_view::size_type>(std::ranges::distance(range))
	};
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
	auto result = _String{};
	std::ranges::copy(range, std::back_inserter(result));
	return result;
}

template<
	IsAnyOf<char8_t, char> _Char, 
	IsByte _Byte, 
	typename _String = std::basic_string_view<_Char>
>
[[nodiscard]] 
auto data_to_string(std::span<_Byte> const data) -> _String {
	return _String{reinterpret_cast<_Char const*>(data.data()), data.size()};
}

template<IsByte _Byte>
[[nodiscard]]
auto string_to_data(IsByteStringView auto string) -> std::span<_Byte const> {
	return std::span{reinterpret_cast<_Byte const*>(string.data()), string.size()};
}

//---------------------------------------------------------


template<std::integral T>
auto string_to_integral(IsByteStringView auto const string, int base = 10) -> std::optional<T> {
	auto number_result = T{};
	auto const char_pointer = reinterpret_cast<char const*>(string.data());
	if (std::from_chars(char_pointer, char_pointer + string.size(), number_result, base).ec == std::errc{}) {
		return number_result;
	}
	return {};
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
constexpr auto find_if(_Range&& range, _Predicate&& predicate) noexcept 
	-> std::optional<_Iterator> 
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

constexpr auto ascii_lowercase_transform = std::views::transform([](char c) { 
	return static_cast<char>(std::tolower(c));
});

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
	Unknown = -1, 
};

constexpr auto get_port(Protocol protocol) noexcept -> Port {
	return static_cast<Port>(protocol);
}

template<IsByteStringView _StringView>
auto get_protocol_from_string(_StringView const protocol_string) noexcept 
	-> Protocol 
{
	auto const ascii_string = [&] {	
		if constexpr (std::same_as<_StringView, std::u8string_view>) {
			return u8string_to_utf8_string(protocol_string);
		}
		else {
			return protocol_string;
		}
	}();
	if (equal_ascii_case_insensitive(ascii_string, "http")) 
	{
		return Protocol::Http;
	}
	else if (equal_ascii_case_insensitive(ascii_string, "https")) {
		return Protocol::Https;
	}
	return Protocol::Unknown;
}

/*
	The result of the split_url function.
*/
template<IsByteChar _Char>
struct SplitUrl {
	Protocol protocol{Protocol::Unknown};
	std::basic_string_view<_Char> domain_name, path;
};

/*
	Splits an URL into a server/domain name and file path.
*/
template<IsByteStringView _StringView, typename _Char = _StringView::value_type>
[[nodiscard]] 
inline auto split_url(_StringView const url) noexcept 
	-> SplitUrl<_Char>
{
	using namespace std::string_view_literals;
	
	if (url.empty()) {
		return {};
	}

	constexpr auto default_protocol = Protocol::Https;
	
	constexpr auto whitespace_characters = select_on_type<_StringView>(u8" \t\r\n"sv, " \t\r\n"sv);
	auto start_position = url.find_first_not_of(whitespace_characters);
	if (start_position == _StringView::npos) {
		return {};
	}
	
	auto result = SplitUrl<_Char>{};

	constexpr auto protocol_suffix = select_on_type<_StringView>(u8"://"sv, "://"sv);
	if (auto const position = url.find(protocol_suffix, start_position);
		position != _StringView::npos) 
	{
		result.protocol = get_protocol_from_string(url.substr(start_position, position - start_position));
		start_position = position + protocol_suffix.length();
	}
	if (result.protocol == Protocol::Unknown) {
		result.protocol = default_protocol;
	}

	if (auto const position = url.find(select_on_type<_Char>(u8'/', '/'), start_position);
		position != std::u8string_view::npos)
	{
		result.domain_name = url.substr(start_position, position - start_position);
		start_position = position;
	}
	else {
		result.domain_name = url.substr(start_position);
		result.path = select_on_type<_StringView>(u8"/"sv, "/"sv);
		return result;
	}

	auto const end_position = url.find_last_not_of(whitespace_characters) + 1;
	result.path = url.substr(start_position, end_position - start_position);
	return result;
}

/*
	Returns the file name part of a URL (or file path with only forward slashes).
*/
template<IsByteStringView _StringView, typename _Char = _StringView::value_type>
constexpr auto extract_filename(_StringView const url) noexcept 
	-> _StringView
{
	if (auto const slash_pos = url.rfind(select_on_type<_Char>(u8'/', '/'));
		slash_pos != std::u8string_view::npos)
	{
		if (auto const question_mark_pos = url.find(select_on_type<_Char>(u8'?', '?'), slash_pos + 1);
			question_mark_pos != std::u8string_view::npos)
		{
			return url.substr(slash_pos + 1, question_mark_pos - slash_pos - 1);
		}

		return url.substr(slash_pos + 1);
	}
	return {};
}

constexpr auto get_is_allowed_uri_character(char const character) noexcept 
	-> bool 
{
	constexpr auto other_characters = std::string_view{"-._~:/?#[]@!$&'()*+,;="};
	
	return character >= '0' && character <= '9' || 
		character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		other_characters.find(character) != std::string_view::npos;
}

} // namespace utils

//---------------------------------------------------------

// TODO: Add forwarding of error messages from APIs such as OpenSSL.

/*
	A minimal collection of internet related errors you should catch and handle yourself.
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
struct ConnectionFailed {	
	bool was_tls_failure{};
};

} // namespace errors

//---------------------------------------------------------

using DataVector = std::vector<std::byte>;

//---------------------------------------------------------

struct ConnectionClosed {};

/*
	A thin abstraction on top of low level socket and TLS APIs.
*/
class Socket {
public:
	/*
	*/
	auto write(std::span<std::byte const> data) const -> void;
	/*
	*/
	auto write(utils::IsByteStringView auto string) const -> void {
		write(std::span{reinterpret_cast<std::byte const*>(string.data()), string.length() + 1});
	}

	/*
	*/
	[[nodiscard]]
	auto read(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t>;
	/*
	*/
	[[nodiscard]]
	auto read(std::size_t const number_of_bytes = 512) const -> std::variant<ConnectionClosed, DataVector> {
		auto result = DataVector(number_of_bytes);
		if (auto const read_result = read(result); std::holds_alternative<std::size_t>(read_result)) {
			result.resize(std::get<std::size_t>(read_result));
			return result;
		}
		return ConnectionClosed{};
	}

	/*
	*/
	[[nodiscard]]
	auto read_available(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t>;
	/*
	*/
	[[nodiscard]]
	auto read_available() const -> std::variant<ConnectionClosed, DataVector> {
		constexpr auto read_buffer_size = 512;

		auto buffer = DataVector(read_buffer_size);
		auto read_offset = std::size_t{};

		while (true) {
			if (auto const read_result = read_available(
					std::span{buffer.data() + read_offset, read_buffer_size}
				); std::holds_alternative<std::size_t>(read_result))
			{
				if (auto const bytes_read = std::get<std::size_t>(read_result)) {
					read_offset += bytes_read;
					buffer.resize(read_offset + read_buffer_size);
				}
				else return buffer;
			}
			else return ConnectionClosed{};
		}
		return {};
	}

	/*
		Returns true if the connection is currently closed.
		The peer may shut down the connection at any time.

		write() reconnects the socket automatically if it closed.
		read() and read_available() return 0 or empty vectors if the connection is closed.
	*/
	// auto get_is_closed() const -> bool;
	/*
		Shuts down the connection with the peer.
		Calling this function sends a message to the peer that indicates
		that we are done sending data. Other, protocol-defined ways of indicating
		the end of the sent data should be used instead of calling this member function, since
		the socket needs to be recreated and reconnected to send more data again.
		For example, http 1.1 uses an empty line, content-length or the chunked transfer encoding
		to indicate the end of requests or responses.

		write() reconnects the socket automatically if it closed.
		read() and read_available() will still read any response data from the peer.
	*/
	// auto close() const -> void;

	Socket() = delete;
	~Socket(); // = default in .cpp

	Socket(Socket&&); // = default in .cpp
	auto operator=(Socket&&) -> Socket&; // = default in .cpp

	Socket(Socket const&) = delete;
	auto operator=(Socket const&) -> Socket& = delete;

private:
	class Implementation;
	std::unique_ptr<Implementation> m_implementation;
	
	Socket(std::u8string_view server, utils::Port port);
	friend auto open_socket(std::u8string_view server, utils::Port port) -> Socket;
};

[[nodiscard]]
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

	[[nodiscard]]
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
[[nodiscard]]
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
	
		/*
			"An HTTP header consists of its case-insensitive name followed by a colon (:), 
			then by its value. Whitespace before the value is ignored." 
			(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

			So we're just ignoring whitespace before the value, and after because there may be
			an \r there if the line endings are CRLF.
		*/

		auto const colon_pos = line.find(':');
		if (colon_pos == std::u8string_view::npos) {
			continue;
		}
		
		constexpr auto whitespace_characters = std::string_view{" \t\r"};
		
		auto const value_start = line.find_first_not_of(whitespace_characters, colon_pos + 1);
		if (value_start == std::string_view::npos) {
			continue;
		}
		
		// This will never be npos, assuming the header 
		// string isn't mutated by some other thread.
		auto const value_end = line.find_last_not_of(whitespace_characters);
		
		result.push_back(Header{
			.name = line.substr(0, colon_pos), 
			.value = line.substr(value_start, value_end + 1 - value_start)
		});
	}

	return result;
}

[[nodiscard]]
inline auto find_header_by_name(std::span<Header> const headers, std::string_view const name) 
	-> std::optional<std::span<Header>::iterator>
{
	auto const lowercase_name_to_search = utils::range_to_string(
		name | utils::ascii_lowercase_transform
	);
	return utils::find_if(headers, [&](auto const& header) {
		return std::ranges::equal(lowercase_name_to_search, header.name | utils::ascii_lowercase_transform);
	});
}

} // namespace algorithms

//---------------------------------------------------------

struct ParsedResponse {
	std::string headers_string;
	std::vector<Header> headers;
	DataVector body_data;
};

class ChunkyBodyParser {
private:
	DataVector m_result;

	std::optional<std::size_t> m_chunk_size_left;
	
public:
	auto parse_new_data(std::span<std::byte const> const new_data) -> std::optional<DataVector> {
		auto const data_string = utils::data_to_string<char>(new_data);
		
		if (m_chunk_size_left) {
			
		}
		else {
			m_chunk_size_left = utils::string_to_integral<std::size_t>(data_string, 16); // hexadecimal
		}
	}
};

class ResponseParser {
private:
	DataVector m_buffer;

	ParsedResponse m_result;

	std::size_t m_body_start{};
	std::size_t m_body_size{};

	[[nodiscard]]
	auto get_body_size() -> std::optional<std::size_t> {
		if (auto const content_length_string = 
				algorithms::find_header_by_name(m_result.headers, "content-length")) 
		{
			if (auto const parse_result = 
					utils::string_to_integral<std::size_t>((*content_length_string)->value)) 
			{
				return *parse_result;
			}
		}
		return {};
	}
	
	[[nodiscard]]
	auto try_extract_headers_string(std::size_t new_data_start) -> std::optional<std::string_view> {
		for (std::string_view const empty_line : {"\r\n\r\n", "\n\n"})
		{
			auto const find_start = static_cast<std::size_t>(std::max(std::int64_t{}, 
				static_cast<std::int64_t>(new_data_start - empty_line.length() + 1)
			));
			
			auto const string_view_to_search = utils::data_to_string<char>(std::span{m_buffer});

			if (auto const position = string_view_to_search.find(empty_line, find_start);
				position != std::string_view::npos) 
			{
				m_body_start = position + empty_line.length();
				return string_view_to_search.substr(0, position);
			}
		}
		return {};
	}

	auto try_parse_headers(std::size_t new_data_start) -> void {
		if (auto const headers_string = try_extract_headers_string(new_data_start))
		{
			m_result.headers_string = *headers_string;
			m_result.headers = algorithms::parse_headers_string(*headers_string);

			if (auto const body_size_try = get_body_size()) {
				m_body_size = *body_size_try;
			}
			else if (auto const transfer_encoding = 
					algorithms::find_header_by_name(m_result.headers, "transfer-encoding");
				transfer_encoding && *transfer_encoding == "chunked")
			{
				m_chunky_body_parser = ChunkyBodyParser{};
				m_chunky_body_parser.parse_new_data({m_buffer.begin() + m_body_start, m_buffer.end()});
			}
		}
	}

	std::optional<ChunkyBodyParser> m_chunky_body_parser;

public:
	[[nodiscard]]
	auto parse_new_data(std::span<std::byte const> const data) -> std::optional<ParsedResponse> {
		auto const new_data_start = m_buffer.size();
		
		m_buffer.insert(m_buffer.end(), data.begin(), data.end());
		
		if (m_result.headers_string.empty()) {
			try_parse_headers(new_data_start);
		}
		if (!m_result.headers_string.empty()) {
			if (m_chunky_body_parser) {
				if (auto const body = m_chunky_body_parser.parse_new_data(data)) {
					m_result.body_data = std::move(*body);
					return m_result;
				}
			}
			else if (m_buffer.size() >= m_body_start + m_body_size) {
				auto const body_begin = m_buffer.begin() + m_body_start;
				m_result.body_data = DataVector(body_begin, body_begin + m_body_size);
				return m_result;
			}
		}
		return {};
	}
};

/*
	Represents the response of a HTTP "GET" request.
*/
class GetResponse {
	friend class GetRequest;

private:
	Socket m_socket;

	std::optional<ParsedResponse> mutable m_parsed_response;

	auto read_response() const -> void {
		auto response_parser = ResponseParser{};

		constexpr auto buffer_size = 512;
		auto read_buffer = std::array<std::byte, buffer_size>();
		
		while (true) {
			if (auto const read_result = m_socket.read(read_buffer);
				std::holds_alternative<std::size_t>(read_result))
			{
				if (auto const parse_result = response_parser.parse_new_data(
						std::span{read_buffer.data(), std::get<std::size_t>(read_result)}
					))
				{
					m_parsed_response = std::move(parse_result);
					break;
				}
			}
			else { // Connection closed
				throw errors::ConnectionFailed{};
			}			
		}
	}

public:
	/*
		Returns the headers of the GET response as a string.
		The returned string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers_string() const -> std::string_view {
		if (!m_parsed_response) {
			read_response();
		}
		return m_parsed_response->headers_string;
	}

private:
	[[nodiscard]]
	auto find_header(std::string_view const name_to_find) const
		-> std::optional<std::span<Header>::iterator>
	{
		if (!m_parsed_response) {
			read_response();
		}
		return algorithms::find_header_by_name(m_parsed_response->headers, name_to_find);
	}

public:
	/*
		Returns the headers of the GET response as Header objects.
		The returned span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_headers() const -> std::span<Header> {
		if (!m_parsed_response) {
			read_response();
		}
		return m_parsed_response->headers;
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
	
	/*
		Returns the body of the GET response.
		The returned std::span shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]]
	auto get_body() const -> std::span<std::byte> {
		if (!m_parsed_response) {
			read_response();
		}
		return m_parsed_response->body_data;
	}
	/*
		Returns the body of the GET response as a string.
		The returned std::u8string_view shall not outlive this GetResponse object.
		I wish there was a way to statically enforce this in c++.
	*/
	[[nodiscard]] 
	auto get_body_string() const -> std::u8string_view
	{
		return utils::data_to_string<char8_t>(get_body());
	}

	// TODO: support unicode file names by creating our own simple file I/O API. 
	// The standard library sucks at unicode.
	
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
	std::string m_headers{"\r\n"};
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
		
		for (auto const& header : headers) {
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
	utils::SplitUrl<char8_t> m_split_url;
	Socket m_socket;

public:
	/*
		Sends the GET request.
	*/
	[[nodiscard]] 
	auto send() && -> GetResponse {
		// TODO: Use std::format when it has been implemented by compilers.
		auto const request_string = (((((std::string{"GET "} += utils::u8string_to_utf8_string(m_split_url.path)) += 
			" HTTP/1.1\r\nHost: ") += utils::u8string_to_utf8_string(m_split_url.domain_name)) += m_headers) += "\r\n");
		m_socket.write(std::string_view{request_string});
		return GetResponse{std::move(m_socket)};
	}

	GetRequest() = delete;
	~GetRequest() = default;

	GetRequest(GetRequest&&) = default;
	auto operator=(GetRequest&&) -> GetRequest& = default;

	GetRequest(GetRequest const&) = delete;
	auto operator=(GetRequest const&) -> GetRequest& = delete;

private:
	friend auto get(std::u8string_view url) -> GetRequest;
	GetRequest(std::u8string_view const url) :
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

} // namespace internet_client
