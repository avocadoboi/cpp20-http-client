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

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <concepts>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <variant>

#if __has_include(<source_location>)
#	include <source_location>
#elif __has_include(<experimental/source_location>)
#	include <experimental/source_location>
	namespace std {
		using source_location = std::experimental::source_location;
	}
#endif

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

using Port = int;

/*
	An enumeration of the communication protocols that are supported by the library.
*/
enum class Protocol : Port {
	Http = 80,
	Https = 443,
	Unknown = -1, 
};

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
	else return select_on_type<T>(std::forward<V>(items)...);
}

//---------------------------------------------------------

template<typename T> requires requires(T callable) { callable(); }
class [[nodiscard]] Cleanup {
private:
	T _callable;
	
public:
	[[nodiscard]] 
	Cleanup(T&& callable) :
		_callable{std::forward<T>(callable)}
	{}

	Cleanup() = delete;
	~Cleanup() {
		_callable();
	}

	Cleanup(Cleanup&&) noexcept = delete;
	auto operator=(Cleanup&&) noexcept -> Cleanup& = delete;

	Cleanup(Cleanup const&) = delete;
	auto operator=(Cleanup const&) -> Cleanup& = delete;
};

//---------------------------------------------------------

/*
	This can be called when the program reaches a path that should never be reachable.
	It prints error output and exits the program.
*/
#ifdef __cpp_lib_source_location
[[noreturn]]
inline auto unreachable(std::source_location const& source_location = std::source_location::current()) -> void {
	// TODO: use std::format when supported
	// std::cerr << std::format("Reached an unreachable code path in file {}, in function {}, on line {}.", 
	// 	source_location.file_name(), source_location.function_name(), source_location.line());
	std::cerr << "Reached an unreachable code path in file " << source_location.file_name() << 
		", in function " << source_location.function_name() << ", on line " << source_location.line() << ".\n";
	std::exit(1);
}
#else
[[noreturn]]
inline auto unreachable() -> void {
	std::cerr << "Reached an unreachable code path, exiting.\n";
	std::exit(1);
}
#endif

/*
	Prints an error message to the error output stream and exits the program.
*/
[[noreturn]]
inline auto panic(std::string_view const message) -> void {
	std::cerr << message << '\n';
	std::exit(1);
}

//---------------------------------------------------------

template<typename T>
concept IsTrivial = std::is_trivial_v<T>;

template<typename _Functor, typename ... _Arguments>
concept IsFunctorInvocable = requires(_Arguments ... arguments) {
	_Functor{}(arguments...);
};

template<typename T>
concept IsByte = sizeof(T) == 1 && IsTrivial<std::remove_reference_t<T>>;

template<typename T>
concept IsByteChar = IsAnyOf<T, char, char8_t>;

template<typename T>
concept IsByteStringView = IsAnyOf<T, std::string_view, std::u8string_view>;

template<typename T>
concept IsByteString = IsAnyOf<T, std::string, std::u8string>;

//---------------------------------------------------------

/*
	Creates T with the same constness as U.
*/
template<typename T, typename U>
using MatchConst = std::conditional_t<std::same_as<U, U const>, T const, std::remove_const_t<T>>;

//---------------------------------------------------------

/*
	Converts a std::u8string_view to a std::string_view, by using the same exact bytes; there's no encoding
	conversion here. The returned std::string_view points to the same data, and is thus utf-8 encoded as well.
	This is only meant to be used to interoperate with APIs that assume regular strings to be utf-8 encoded.
*/
[[nodiscard]] 
inline auto u8string_to_utf8_string(std::u8string_view const u8string) noexcept 
	-> std::string_view 
{
	return {
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
	IsByteChar _Char = std::ranges::range_value_t<_Range>
> 
[[nodiscard]] 
constexpr auto range_to_string_view(_Range const& range) 
	-> std::basic_string_view<_Char>
{
	return {
		&*std::begin(range), 
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
	IsByteChar _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string<_Char>
> 
[[nodiscard]]
inline auto range_to_string(_Range const& range) -> _String {
	auto result = _String(range.size(), _Char{});
	std::ranges::copy(range, std::begin(result));
	return result;
}

/*
	Copies a range of unknown size to a std::basic_string of any type.
*/
template<
	std::ranges::range _Range,
	IsByteChar _Char = std::ranges::range_value_t<_Range>,
	typename _String = std::basic_string_view<_Char>
> 
[[nodiscard]]
inline auto range_to_string(_Range const& range) -> _String {
	auto result = _String{};
	std::ranges::copy(range, std::back_inserter(result));
	return result;
}

template<
	IsByteChar _Char, 
	IsByte _Byte, 
	typename _String = std::basic_string_view<_Char>
>
[[nodiscard]] 
auto data_to_string(std::span<_Byte> const data) -> _String {
	return _String{reinterpret_cast<_Char const*>(data.data()), data.size()};
}

template<IsByte _Byte>
[[nodiscard]]
auto string_to_data(IsByteStringView auto const string) -> std::span<_Byte const> {
	return std::span{reinterpret_cast<_Byte const*>(string.data()), string.size()};
}

//---------------------------------------------------------

using DataVector = std::vector<std::byte>;

//---------------------------------------------------------

template<std::movable T>
auto append_to_vector(std::vector<T>& vector, std::span<T const> const data) -> void {
	vector.insert(vector.end(), data.begin(), data.end());
}

//---------------------------------------------------------

template<typename T>
concept IsByteData = IsByte<T> || std::ranges::range<T> && IsByte<std::ranges::range_value_t<T>>;

template<IsByteData T> 
[[nodiscard]]
auto size_of_byte_data(T&& data) -> std::size_t {
	if constexpr (requires{ std::size(data); }) {
		return std::size(data);
	}
	else {
		return sizeof(data);
	}
}

/*
	Copies any type of trivial byte-sized element(s) from data to range.
*/
template<IsByteData _Data, std::ranges::contiguous_range _Range, IsByte _RangeValue = std::ranges::range_value_t<_Range>> 
[[nodiscard]]
auto copy_byte_data(_Data&& data, _Range&& range) 
	-> std::ranges::iterator_t<_Range> 
{
	if constexpr (IsByte<_Data>) {
		*std::begin(range) = *reinterpret_cast<_RangeValue*>(&data);
		return std::begin(range) + 1;
	}
	else {
		return std::ranges::copy(std::span{reinterpret_cast<_RangeValue const*>(std::data(data)), std::size(data)}, std::begin(range)).out;
	}
}

/*
	Concatenates any kind of sequence of trivial byte-sized elements like char and std::byte.
	The arguments can be individual bytes and/or ranges of bytes.
	Returns a utils::DataVector (std::vector<std::byte>).
*/
template<IsByteData ... T>
[[nodiscard]]
auto concatenate_byte_data(T&& ... arguments) -> DataVector {
	auto buffer = DataVector((size_of_byte_data(arguments) + ...));
	auto buffer_span = std::span{buffer};
	((buffer_span = std::span{copy_byte_data(arguments, buffer_span), buffer_span.end()}), ...);
	return buffer;
}

//---------------------------------------------------------

/*
	Parses a string as an integer type in a given base.
	For more details, see std::from_chars. This is just an abstraction layer on top of it.
*/
template<std::integral T>
[[nodiscard]]
auto string_to_integral(IsByteStringView auto const string, int const base = 10) -> std::optional<T> {
	auto number_result = T{};
	auto const char_pointer = reinterpret_cast<char const*>(string.data());
	if (std::from_chars(char_pointer, char_pointer + string.size(), number_result, base).ec == std::errc{}) {
		return number_result;
	}
	return {};
}

// template<IsByteChar _Char>
// auto integral_to_string(std::integral auto number) -> std::

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
	if (auto const end = std::end(range), 
	    	pos = std::ranges::find_if(std::forward<_Range>(range), std::forward<_Predicate>(predicate)); 
		pos == end)
	{
		return {};
	}
	else return pos;
}

constexpr auto ascii_lowercase_transform = std::views::transform([](char c) { 
	return static_cast<char>(std::tolower(c));
});

[[nodiscard]]
constexpr auto equal_ascii_case_insensitive(std::string_view const lhs, std::string_view const rhs) noexcept -> bool {
	return std::ranges::equal(lhs | ascii_lowercase_transform, rhs | ascii_lowercase_transform);
}

//---------------------------------------------------------

[[nodiscard]]
constexpr auto get_port(Protocol protocol) noexcept -> Port {
	return static_cast<Port>(protocol);
}

template<IsByteStringView _StringView>
[[nodiscard]]
auto get_protocol_from_string(_StringView const protocol_string) noexcept 
	-> Protocol 
{
	auto const ascii_string = [&] {	
		if constexpr (std::same_as<_StringView, std::u8string_view>) {
			return u8string_to_utf8_string(protocol_string);
		}
		else return protocol_string;
	}();
	if (equal_ascii_case_insensitive(ascii_string, "http")) {
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
inline auto split_url(_StringView const url) 
	-> SplitUrl<_Char>
{
	using namespace std::string_view_literals;
	
	if (url.empty()) {
		return {};
	}

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
[[nodiscard]]
constexpr auto extract_filename(_StringView const url) 
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

[[nodiscard]]
constexpr auto get_is_allowed_uri_character(char const character) noexcept -> bool {
	constexpr auto other_characters = std::string_view{"%-._~:/?#[]@!$&'()*+,;="};
	
	return character >= '0' && character <= '9' || 
		character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		other_characters.find(character) != std::string_view::npos;
}

template<
	IsByteStringView _StringView, 
	typename _Char = _StringView::value_type, 
	typename _String = std::basic_string<_Char>
>
[[nodiscard]]
auto uri_encode(_StringView const uri) -> _String {
	using namespace std::string_view_literals;
	
	auto result_string = _String();
	result_string.reserve(uri.size());

	for (auto const character : uri) {
		if (get_is_allowed_uri_character(character)) {
			result_string += character;
		}
		else {
			result_string += select_on_type<_StringView>("%xx"sv, u8"%xx"sv);
			std::to_chars(
				reinterpret_cast<char*>(&result_string.back() - 1), 
				reinterpret_cast<char*>(&result_string.back() + 1), 
				static_cast<unsigned char>(character), 
				16
			);
		}
	}
	return result_string;
}

} // namespace utils

//---------------------------------------------------------

namespace errors {

/*
	The connection to the server failed in some way.
	For example, there is no internet connection or the server name is invalid.
*/
class ConnectionFailed : public std::exception {
private:
	std::string _reason;
public:
	[[nodiscard]]
	auto what() const noexcept -> char const* override {
		return _reason.c_str();
	}

private:
	bool _is_tls_failure;
public:
	[[nodiscard]]
	auto get_is_tls_failure() const noexcept -> bool {
		return _is_tls_failure;
	}

	ConnectionFailed(std::string reason, bool const is_tls_failure = false) :
		_reason(std::move(reason)),
		_is_tls_failure{is_tls_failure}
	{}
};

class ResponseParsingFailed : public std::exception {
private:
	std::string _reason;
public:
	[[nodiscard]]
	auto what() const noexcept -> char const* override {
		return _reason.c_str();
	}

	ResponseParsingFailed(std::string reason) :
		_reason(std::move(reason))
	{}
};

} // namespace errors

//---------------------------------------------------------

/*
	This type is used by the Socket class to signify that 
	the peer closed the connection during a read call.
*/
struct ConnectionClosed {};

/*
	An abstraction on top of low level socket and TLS encryption APIs.
	Marking a Socket as const only means it won't be moved from or move assigned to.
*/
class Socket {
public:
	/*
		Sends data to the peer through the socket.
	*/
	auto write(std::span<std::byte const> data) const -> void;
	/*
		Sends a string to the peer through the socket.
		This function takes a basic_string_view, think about 
		whether you want it to be null terminated or not.
	*/
	auto write(utils::IsByteStringView auto const string_view) const -> void {
		write(std::span{reinterpret_cast<std::byte const*>(string_view.data()), string_view.length()});
	}
	/*
		Sends a string to the peer through the socket.
	*/
	auto write(utils::IsByteString auto const string) const -> void {
		// Include null terminator
		write(std::span{reinterpret_cast<std::byte const*>(string.data()), string.length() + 1});
	}

	/*
		Receives data from the socket and reads it into a buffer.
		This function blocks until there is some data available.
		The data that was read may be smaller than the buffer.
		The function either returns the number of bytes that were read 
		or a ConnectionClosed value if the peer closed the connection. 
	*/
	[[nodiscard("The result is important as it contains the size that was actually read.")]]
	auto read(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t>;
	/*
		Receives data from the socket.
		This function blocks until there is some data available.
		The function either returns the buffer that was read 
		or a ConnectionClosed value if the peer closed the connection. 
		The returned DataVector may be smaller than what was requested.
	*/
	[[nodiscard]]
	auto read(std::size_t const number_of_bytes = 512) const 
		-> std::variant<ConnectionClosed, utils::DataVector> 
	{
		auto result = utils::DataVector(number_of_bytes);
		if (auto const read_result = read(result); std::holds_alternative<std::size_t>(read_result)) {
			result.resize(std::get<std::size_t>(read_result));
			return result;
		}
		return ConnectionClosed{};
	}

	/*
		Reads any available data from the socket into a buffer.
		This function is nonblocking, and may return std::size_t{} if 
		there was no data available. The function either returns the number 
		of bytes that were read or a ConnectionClosed value if the peer 
		closed the connection.
	*/
	[[nodiscard("The result is important as it contains the size that was actually read.")]]
	auto read_available(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t>;
	/*
		Reads any available data from the socket into a buffer.
		This function is nonblocking, and may return an empty vector if 
		there was no data available. The function either returns a utils::DataVector 
		of the data that was read or a ConnectionClosed value if the peer 
		closed the connection.
	*/
	[[nodiscard]]
	auto read_available() const -> std::variant<ConnectionClosed, utils::DataVector> {
		constexpr auto read_buffer_size = 512;

		auto buffer = utils::DataVector(read_buffer_size);
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

	Socket() = delete;
	~Socket(); // = default in .cpp

	Socket(Socket&&) noexcept; // = default in .cpp
	auto operator=(Socket&&) noexcept -> Socket&; // = default in .cpp
 
	Socket(Socket const&) = delete;
	auto operator=(Socket const&) -> Socket& = delete;

private:
	class Implementation;
	std::unique_ptr<Implementation> _implementation;
	
	Socket(std::u8string_view server, Port port, bool is_tls_encrypted);
	friend auto open_socket(std::u8string_view, Port, bool) -> Socket;
};

/*
	Opens a socket to a server through a port.
	If port is 443 OR is_tls_encrypted is true, TLS encryption is used. 
	Otherwise it is unencrypted.
*/
[[nodiscard]]
inline auto open_socket(std::u8string_view const server, Port const port, bool const is_tls_encrypted = false) -> Socket {
	return Socket{server, port, is_tls_encrypted};
}
/*
	Opens a socket to a server through a port.
	If port is 443 OR is_tls_encrypted is true, TLS encryption is used. 
	Otherwise it is unencrypted.
*/
[[nodiscard]]
inline auto open_socket(std::string_view const server, Port const port, bool const is_tls_encrypted = false) -> Socket {
	return open_socket(utils::utf8_string_to_u8string(server), port, is_tls_encrypted);
}

//---------------------------------------------------------

namespace http {

struct Header;

/*
	Represents a HTTP header whose data was copied from somewhere at some point.
	It consists of std::string objects instead of std::string_view.
*/
struct HeaderCopy {
	std::string name, value;

	[[nodiscard]]
	inline explicit operator Header() const;
};
/*
	Represents a HTTP header whose data is not owned by this object.
	It consists of std::string_view objects instead of std::string.
*/
struct Header {
	std::string_view name, value;

	[[nodiscard]]
	explicit operator HeaderCopy() const {
		return HeaderCopy{
			.name = std::string{name},
			.value = std::string{value},
		};
	}
};
HeaderCopy::operator Header() const {
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

enum class StatusCode {
	Continue = 100,
	SwitchingProtocols = 101,
	Processing = 102,
	EarlyHints = 103,

	Ok = 200,
	Created = 201,
	Accepted = 202,
	NonAuthoritativeInformation = 203,
	NoContent = 204,
	ResetContent = 205,
	PartialContent = 206,
	MultiStatus = 207,
	AlreadyReported = 208,
	ImUsed = 226,

	MultipleChoices = 300,
	MovedPermanently = 301,
	Found = 302,
	SeeOther = 303,
	NotModified = 304,
	UseProxy = 305,
	SwitchProxy = 306,
	TemporaryRedirect = 307,
	PermanentRedirect = 308,

	BadRequest = 400,
	Unauthorized = 401,
	PaymentRequired = 402,
	Forbidden = 403,
	NotFound = 404,
	MethodNotAllowed = 405,
	NotAcceptable = 406,
	ProxyAuthenticationRequired = 407,
	RequestTimeout = 408,
	Conflict = 409,
	Gone = 410,
	LengthRequired = 411,
	PreconditionFailed = 412,
	PayloadTooLarge = 413,
	UriTooLong = 414,
	UnsupportedMediaType = 415,
	RangeNotSatisfiable = 416,
	ExpectationFailed = 417,
	ImATeapot = 418,
	MisdirectedRequest = 421,
	UnprocessableEntity = 422,
	Locked = 423,
	FailedDependency = 424,
	TooEarly = 425,
	UpgradeRequired = 426,
	PreconditionRequired = 428,
	TooManyRequests = 429,
	RequestHeaderFieldsTooLarge = 431,
	UnavailableForLegalReasons = 451,

	InternalServerError = 500,
	NotImplemented = 501,
	BadGateway = 502,
	ServiceUnavailable = 503,
	GatewayTimeout = 504,
	HttpVersionNotSupported = 505,
	VariantAlsoNegotiates = 506,
	InsufficientStorage = 507,
	LoopDetected = 508,
	NotExtended = 510,
	NetworkAuthenticationRequired = 511,

	Unknown = -1
};

struct StatusLine {
	std::string http_version;
	StatusCode status_code = StatusCode::Unknown;
	std::string status_message;

	[[nodiscard]]
	auto operator==(StatusLine const&) const noexcept -> bool = default;
};

namespace algorithms {

[[nodiscard]]
inline auto parse_status_line(std::string_view const line) -> StatusLine {
	auto status_line = StatusLine{};

	auto cursor = size_t{};
	
	if (auto const http_version_end = line.find(' '); http_version_end != std::string_view::npos)
	{
		status_line.http_version = line.substr(0, http_version_end);
		cursor = http_version_end + 1;
	}
	else return status_line;

	if (auto const status_code_end = line.find(' ', cursor); status_code_end != std::string_view::npos) 
	{
		if (auto const status_code = utils::string_to_integral<int>(line.substr(cursor, status_code_end))) 
		{
			status_line.status_code = static_cast<StatusCode>(*status_code);
		}
		else return status_line;
		cursor = status_code_end + 1;
	}
	else return status_line;
	
	status_line.status_message = line.substr(cursor, line.find_last_not_of("\r\n ") + 1 - cursor);
	return status_line;
}

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
inline auto find_header_by_name(std::span<Header const> const headers, std::string_view const name) 
	-> std::optional<std::span<Header const>::iterator>
{
	auto const lowercase_name_to_search = utils::range_to_string(
		name | utils::ascii_lowercase_transform
	);
	return utils::find_if(headers, [&](auto const& header) {
		return std::ranges::equal(lowercase_name_to_search, header.name | utils::ascii_lowercase_transform);
	});
}

struct ParsedResponse {
	StatusLine status_line;
	std::string headers_string;
	std::vector<Header> headers; // Points into headers_string
	utils::DataVector body_data;

	[[nodiscard]]
	auto operator==(ParsedResponse const&) const noexcept -> bool = default;
};

struct ParsedHeadersInterface {
	constexpr virtual auto get_parsed_response() const noexcept -> ParsedResponse const& = 0;

	/*
		Returns the status code from the response header.
	*/
	[[nodiscard]]
	auto get_status_code() const -> StatusCode {
		return get_parsed_response().status_line.status_code;
	}
	/*
		Returns the status code description from the response header.
	*/
	[[nodiscard]]
	auto get_status_message() const -> std::string_view {
		return get_parsed_response().status_line.status_message;
	}
	/*
		Returns the HTTP version from the response header.
	*/
	[[nodiscard]]
	auto get_http_version() const -> std::string_view {
		return get_parsed_response().status_line.http_version;
	}
	/*
		Returns a const reference to the parsed status line object.
	*/
	[[nodiscard]]
	auto get_status_line() const -> StatusLine const& {
		return get_parsed_response().status_line;
	}

	/*
		Returns the headers of the response as a string.
		The returned string_view shall not outlive this Response object.
	*/
	[[nodiscard]] 
	auto get_headers_string() const -> std::string_view {
		return get_parsed_response().headers_string;
	}

	/*
		Returns the headers of the response as Header objects.
		The returned span shall not outlive this Response object.
	*/
	[[nodiscard]] 
	auto get_headers() const -> std::span<Header const> {
		return get_parsed_response().headers;
	}
	/*
		Returns a header of the response by its name.
		The returned header shall not outlive this Response object.
	*/	
	[[nodiscard]] 
	auto get_header(std::string_view const name) const -> std::optional<Header> {
		if (auto const pos = algorithms::find_header_by_name(get_parsed_response().headers, name)) {
			return **pos;
		}
		else return {};
	}
	/*
		Returns a header value of the response by its name.
		The returned std::string_view shall not outlive this Response object.
	*/
	[[nodiscard]] 
	auto get_header_value(std::string_view const name) const -> std::optional<std::string_view> {
		if (auto const pos = algorithms::find_header_by_name(get_parsed_response().headers, name)) {
			return (*pos)->value;
		}
		else return {};
	}
};

class ResponseParser;

} // namespace algorithms

class ResponseProgressRaw {	
	friend class algorithms::ResponseParser;
	
private:
	bool _is_stopped = false;
public:
	constexpr auto stop() noexcept -> void {
		_is_stopped = true;
	}

	std::span<std::byte const> data;
	std::size_t new_data_start;

	explicit constexpr ResponseProgressRaw(std::span<std::byte const> const p_data, std::size_t const p_new_data_start) noexcept :
		data{p_data}, new_data_start{p_new_data_start}
	{}
};

class ResponseProgressHeaders : public algorithms::ParsedHeadersInterface {
public:
	ResponseProgressRaw raw_progress;

	constexpr auto stop() noexcept -> void {
		raw_progress.stop();
	}
	
private:
	algorithms::ParsedResponse const& _parsed_response;
public:
	[[nodiscard]]
	constexpr auto get_parsed_response() const noexcept 
		-> algorithms::ParsedResponse const& override 
	{
		return _parsed_response;
	}

	ResponseProgressHeaders(ResponseProgressRaw const p_raw_progress, algorithms::ParsedResponse const& parsed_response) :
		raw_progress{p_raw_progress}, _parsed_response{parsed_response}
	{}

	ResponseProgressHeaders() = delete;
	~ResponseProgressHeaders() = default;
	
	ResponseProgressHeaders(ResponseProgressHeaders const&) = delete;
	auto operator=(ResponseProgressHeaders const&) -> ResponseProgressHeaders& = delete;

	ResponseProgressHeaders(ResponseProgressHeaders&&) noexcept = delete;
	auto operator=(ResponseProgressHeaders&&) noexcept -> ResponseProgressHeaders& = delete;
};

class ResponseProgressBody : public algorithms::ParsedHeadersInterface {
public:
	ResponseProgressRaw raw_progress;

	constexpr auto stop() noexcept -> void {
		raw_progress.stop();
	}
	
private:
	algorithms::ParsedResponse const& _parsed_response;
public:
	[[nodiscard]]
	constexpr auto get_parsed_response() const noexcept 
		-> algorithms::ParsedResponse const& override 
	{
		return _parsed_response;
	}

	std::span<std::byte const> body_data_so_far;
	/*
		This may not have a value if the transfer encoding is chunked, in which
		case the full body length is not known ahead of time.
	*/
	std::optional<std::size_t> total_expected_body_size;

	ResponseProgressBody(
		ResponseProgressRaw const p_raw_progress, 
		algorithms::ParsedResponse const& parsed_response,
		std::span<std::byte const> const p_body_data_so_far, 
		std::optional<std::size_t> const p_total_expected_body_size
	) : 
		raw_progress{p_raw_progress},
		_parsed_response{parsed_response},
		body_data_so_far{p_body_data_so_far},
		total_expected_body_size{p_total_expected_body_size}
	{}

	ResponseProgressBody() = delete;
	~ResponseProgressBody() = default;
	
	ResponseProgressBody(ResponseProgressBody const&) = delete;
	auto operator=(ResponseProgressBody const&) -> ResponseProgressBody& = delete;

	ResponseProgressBody(ResponseProgressBody&&) noexcept = delete;
	auto operator=(ResponseProgressBody&&) noexcept -> ResponseProgressBody& = delete;
};

/*
	Represents the response of a HTTP request.
*/
class Response : public algorithms::ParsedHeadersInterface {
private:
	algorithms::ParsedResponse _parsed_response;

public:
	[[nodiscard]]
	constexpr auto get_parsed_response() const noexcept
		-> algorithms::ParsedResponse const& override 
	{
		return _parsed_response;
	}
	
	/*
		Returns the body of the response.
		The returned std::span shall not outlive this Response object.
	*/
	[[nodiscard]]
	auto get_body() const -> std::span<std::byte const> {
		return _parsed_response.body_data;
	}
	/*
		Returns the body of the response as a string.
		The returned std::u8string_view shall not outlive this Response object.
	*/
	template<utils::IsByteChar _Char>
	[[nodiscard]] 
	auto get_body_string() const -> std::basic_string_view<_Char> {
		return utils::data_to_string<_Char>(get_body());
	}

	// TODO: support unicode file names by creating our own simple file I/O API. 
	// The standard library sucks at unicode.
	
	/*
		Writes the body of the response to a file with the name file_name.
	*/
	auto write_body_to_file(std::string const& file_name) const -> void {
		// std::string because std::ofstream does not take std::string_view.
		auto const body = get_body();
		auto file_stream = std::ofstream{file_name, std::ios::binary};
		file_stream.write(reinterpret_cast<char const*>(body.data()), body.size());
	}

private:
	std::u8string _url;
public:
	template<utils::IsByteChar _Char>
	[[nodiscard]]
	auto get_url() const -> std::basic_string_view<_Char> {
		return std::basic_string_view<_Char>{reinterpret_cast<_Char const*>(_url.data()), _url.size()};
	}

	Response() = delete;
	~Response() = default;

	Response(Response const&) = delete;
	auto operator=(Response const&) -> Response& = delete;
	
	Response(Response&&) noexcept = default;
	auto operator=(Response&&) noexcept -> Response& = default;

	Response(algorithms::ParsedResponse&& parsed_response, std::u8string&& url) :
		_parsed_response{std::move(parsed_response)},
		_url{std::move(url)}
	{}
};

namespace algorithms {

class ChunkyBodyParser {
private:
	static constexpr auto newline = std::string_view{"\r\n"};

	utils::DataVector _result;
	bool _has_returned_result = false;

	std::size_t _chunk_size_left;

	auto parse_chunk_size_left(std::string_view const string) -> void {
		// hexadecimal
		if (auto const result = utils::string_to_integral<std::size_t>(string, 16)) {
			_chunk_size_left = *result;
		}
		else throw errors::ResponseParsingFailed{"Failed parsing http body chunk size."};
	}

	[[nodiscard]]
	auto parse_chunk_body_part(std::span<std::byte const> const new_data) -> std::size_t {
		if (_chunk_size_left > new_data.size())
		{
			_chunk_size_left -= new_data.size();
			utils::append_to_vector(_result, new_data);
			return new_data.size();
		}
		else {
			utils::append_to_vector(_result, new_data.first(_chunk_size_left));

			// After each chunk, there is a \r\n and then the size of the next chunk.
			// We skip the \r\n so the next part starts at the size number.
			auto const part_end = _chunk_size_left + newline.size();
			_chunk_size_left = 0;
			return part_end;
		}
	}

	std::string _chunk_size_string_buffer;
	bool _is_finished = false;

	[[nodiscard]]
	auto parse_chunk_separator_part(std::span<std::byte const> const new_data) -> std::size_t {
		auto const data_string = utils::data_to_string<char>(new_data);

		auto const first_newline_character_pos = data_string.find(newline[0]);
		if (first_newline_character_pos == std::string_view::npos) {
			_chunk_size_string_buffer += data_string;
			return new_data.size();
		}
		else if (_chunk_size_string_buffer.empty()) {
			parse_chunk_size_left(data_string.substr(0, first_newline_character_pos));
		}
		else {
			_chunk_size_string_buffer += data_string.substr(0, first_newline_character_pos);
			parse_chunk_size_left(_chunk_size_string_buffer);
			_chunk_size_string_buffer.clear();
		}
		if (_chunk_size_left == 0) {
			_is_finished = true;
			return 0;
		}
		return first_newline_character_pos + newline.size();
	}

	/*
		"part" refers to a separately parsed unit of data.
		This paritioning makes the parsing algorithm simpler.
		Returns the position where the part ended.
		It may be past the end of the part.
	*/
	[[nodiscard]]
	auto parse_next_part(std::span<std::byte const> const new_data) -> std::size_t {
		if (_chunk_size_left) {
			return parse_chunk_body_part(new_data);
		}
		else return parse_chunk_separator_part(new_data);
	}
	
	std::size_t _start_parse_offset;

public:
	[[nodiscard]]
	auto parse_new_data(std::span<std::byte const> const new_data) -> std::optional<utils::DataVector> {
		if (_has_returned_result) {
			return {};
		}
		if (_is_finished) {
			_has_returned_result = true;
			return std::move(_result);
		}
		
		auto cursor = _start_parse_offset;
		
		while (true) {
			if (cursor >= new_data.size()) {
				_start_parse_offset = cursor - new_data.size();
				return {};
			}
			if (auto const cursor_offset = parse_next_part(new_data.subspan(cursor))) {
				cursor += cursor_offset;
			}
			else {
				_has_returned_result = true;
				return std::move(_result);
			}
		}
	}
	[[nodiscard]]
	auto get_result_so_far() -> std::span<std::byte const> {
		return _result;
	}
};

struct ResponseCallbacks {
	std::function<void(ResponseProgressRaw&)> handle_raw_progress;
	std::function<void(ResponseProgressHeaders&)> handle_headers;
	std::function<void(ResponseProgressBody&)> handle_body_progress;
	std::function<void(Response&)> handle_finish;
	std::function<void()> handle_stop;
};

/*
	Separate, testable module that parses a http response.
	It has support for optional response progress callbacks.
*/
class ResponseParser {
private:
	utils::DataVector _buffer;

	std::optional<ResponseCallbacks*> _callbacks;

	ParsedResponse _result;
	bool _is_done = false;

	auto finish() -> void {
		_is_done = true;
		if (_callbacks && (*_callbacks)->handle_stop) {
			(*_callbacks)->handle_stop();
		}
	}

	std::size_t _body_start{};
	std::size_t _body_size{};

	[[nodiscard]]
	auto get_body_size() -> std::optional<std::size_t> {
		if (auto const content_length_string = 
				algorithms::find_header_by_name(_result.headers, "content-length")) 
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
	auto try_extract_headers_string(std::size_t const new_data_start) -> std::optional<std::string_view> {
		// '\n' line endings are not conformant with the HTTP standard.
		for (std::string_view const empty_line : {"\r\n\r\n", "\n\n"})
		{
			auto const find_start = static_cast<std::size_t>(std::max(std::int64_t{}, 
				static_cast<std::int64_t>(new_data_start - empty_line.length() + 1)
			));
			
			auto const string_view_to_search = utils::data_to_string<char>(std::span{_buffer});

			if (auto const position = string_view_to_search.find(empty_line, find_start);
				position != std::string_view::npos) 
			{
				_body_start = position + empty_line.length();
				return string_view_to_search.substr(0, position);
			}
		}
		return {};
	}

	auto try_parse_headers(std::size_t const new_data_start) -> void {
		if (auto const headers_string = try_extract_headers_string(new_data_start))
		{
			_result.headers_string = *headers_string;

			auto status_line_end = _result.headers_string.find_first_of("\r\n");
			if (status_line_end == std::string_view::npos) {
				status_line_end = _result.headers_string.size();
			}
			
			_result.status_line = algorithms::parse_status_line(
				std::string_view{_result.headers_string}.substr(0, status_line_end)
			);

			if (_result.headers_string.size() > status_line_end) {
				_result.headers = algorithms::parse_headers_string(
					std::string_view{_result.headers_string}.substr(status_line_end)
				);
			}

			if (_callbacks && (*_callbacks)->handle_headers) {
				auto progress_headers = ResponseProgressHeaders{ResponseProgressRaw{_buffer, new_data_start}, _result};
				(*_callbacks)->handle_headers(progress_headers);
				if (progress_headers.raw_progress._is_stopped) {
					finish();
				}
			}

			if (auto const body_size_try = get_body_size()) {
				_body_size = *body_size_try;
			}
			else if (auto const transfer_encoding = 
					algorithms::find_header_by_name(_result.headers, "transfer-encoding");
				transfer_encoding && (*transfer_encoding)->value == "chunked")
			{
				_chunky_body_parser = ChunkyBodyParser{};
			}
		}
	}

	std::optional<ChunkyBodyParser> _chunky_body_parser;

	auto parse_new_chunky_body_data(std::size_t const new_data_start) -> void {
		// May need to add an offset if this packet is
		// where the headers end and the body starts.
		auto const body_parse_start = std::max(new_data_start, _body_start);
		if (auto const body = _chunky_body_parser->parse_new_data(std::span{_buffer}.subspan(body_parse_start))) 
		{
			_result.body_data = std::move(*body);

			if (_callbacks && (*_callbacks)->handle_body_progress) {
				auto body_progress = ResponseProgressBody{
					ResponseProgressRaw{_buffer, new_data_start}, 
					_result, 
					_result.body_data, {}
				};
				(*_callbacks)->handle_body_progress(body_progress);
			}
			
			finish();
		}
		else if (_callbacks && (*_callbacks)->handle_body_progress) {
			auto body_progress = ResponseProgressBody{
				ResponseProgressRaw{_buffer, new_data_start}, 
				_result, 
				_chunky_body_parser->get_result_so_far(), {}
			};
			(*_callbacks)->handle_body_progress(body_progress);
			if (body_progress.raw_progress._is_stopped) {
				finish();
			}
		}
	}

	auto parse_new_regular_body_data(std::size_t const new_data_start) -> void {
		if (_buffer.size() >= _body_start + _body_size) {
			auto const body_begin = _buffer.begin() + _body_start;
			_result.body_data = utils::DataVector(body_begin, body_begin + _body_size);

			if (_callbacks && (*_callbacks)->handle_body_progress) {
				auto body_progress = ResponseProgressBody{
					ResponseProgressRaw{_buffer, new_data_start}, 
					_result, 
					_result.body_data, 
					_body_size
				};
				(*_callbacks)->handle_body_progress(body_progress);
			}

			finish();
		}
		else if (_callbacks && (*_callbacks)->handle_body_progress) {
			auto body_progress = ResponseProgressBody{
				ResponseProgressRaw{_buffer, new_data_start}, 
				_result, 
				std::span{_buffer}.subspan(_body_start), 
				_body_size
			};
			(*_callbacks)->handle_body_progress(body_progress);
			if (body_progress.raw_progress._is_stopped) {
				finish();
			}
		}
	}

public:
	/*
		Parses a new packet of data from the HTTP response.
		If it reached the end of the response, the parsed result is returned.
	*/
	[[nodiscard]]
	auto parse_new_data(std::span<std::byte const> const data) -> std::optional<ParsedResponse> {
		if (_is_done) {
			return {};
		}
		
		auto const new_data_start = _buffer.size();
		
		utils::append_to_vector(_buffer, data);

		if (_callbacks && (*_callbacks)->handle_raw_progress) {
			auto raw_progress = ResponseProgressRaw{_buffer, new_data_start};
			(*_callbacks)->handle_raw_progress(raw_progress);
			if (raw_progress._is_stopped) {
				finish();
			}
		}
		
		if (!_is_done && _result.headers_string.empty()) {
			try_parse_headers(new_data_start);
		}

		if (!_is_done && !_result.headers_string.empty()) {
			if (_chunky_body_parser) {
				parse_new_chunky_body_data(new_data_start);
			}
			else {
				parse_new_regular_body_data(new_data_start);
			}
		}
		if (_is_done) {
			return std::move(_result);
		}
		return {};
	}

	ResponseParser() = default;
	ResponseParser(ResponseCallbacks& callbacks) :
		_callbacks{&callbacks}
	{}
};

[[nodiscard]]
inline auto receive_response(Socket const&& socket, std::u8string&& url, ResponseCallbacks&& callbacks) -> Response {
	auto has_stopped = false;
	callbacks.handle_stop = [&has_stopped]{ has_stopped = true; };
	
	auto response_parser = algorithms::ResponseParser{callbacks};

	constexpr auto buffer_size = std::size_t{1} << 12;
	auto read_buffer = std::array<std::byte, buffer_size>();
	
	while (!has_stopped) {
		if (auto const read_result = socket.read(read_buffer);
			std::holds_alternative<std::size_t>(read_result))
		{
			if (auto parse_result = response_parser.parse_new_data(
					std::span{read_buffer}.first(std::get<std::size_t>(read_result))
				))
			{
				auto response = Response{std::move(*parse_result), std::move(url)};
				if (callbacks.handle_finish) {
					callbacks.handle_finish(response);
				}
				return response;
			}
		}
		else throw errors::ConnectionFailed{"The peer closed the connection unexpectedly"};
	}

	utils::unreachable();
}

} // namespace algorithms

//---------------------------------------------------------

enum class RequestMethod {
	Connect,
	Delete,
	Get,
	Head,
	Options,
	Patch,
	Post,
	Put,
	Trace,
};

[[nodiscard]]
inline auto request_method_to_string(RequestMethod method) -> std::string_view {
	// TODO: Use using enum declarations when supported by gcc.
	// using enum RequestMethod;
	switch (method) {
		case RequestMethod::Connect: return "CONNECT";
		case RequestMethod::Delete:  return "DELETE";
		case RequestMethod::Get:     return "GET";
		case RequestMethod::Head:    return "HEAD";
		case RequestMethod::Options: return "OPTIONS";
		case RequestMethod::Patch:   return "PATCH";
		case RequestMethod::Post:    return "POST";
		case RequestMethod::Put:     return "PUT";
		case RequestMethod::Trace:   return "TRACE";
	}
	utils::unreachable();
}

/*
	Represents a HTTP request.
	It is created by calling any of the HTTP verb functions (http::get, http::post, http::put ...)
*/
class Request {
private:
	std::string _headers{"\r\n"};

public:
	/*
		Adds headers to the request as a string.
		These are in the format: "NAME: [ignored whitespace] VALUE"
		The string can be multiple lines for multiple headers.
		Non-ASCII bytes are considered opaque data,
		according to the HTTP specification.
	*/
	[[nodiscard]]
	auto add_headers(std::string_view const headers_string) && -> Request&& {
		if (headers_string.empty()) {
			return std::move(*this);
		}
		
		_headers += headers_string;
		if (headers_string.back() != '\n') {
			_headers += "\r\n"; // CRLF is the correct line ending for the HTTP protocol
		}
		
		return std::move(*this);
	}
	/*
		Adds headers to the request.
	*/
	template<IsHeader _Header, std::size_t extent = std::dynamic_extent>
	[[nodiscard]]
	auto add_headers(std::span<_Header const, extent> const headers) && -> Request&& {
		auto headers_string = std::string{};
		headers_string.reserve(headers.size()*128);
		
		for (auto const& header : headers) {
			// TODO: Use std::format when it has been implemented by compilers.
			(((headers_string += header.name) += ": ") += header.value) += "\r\n";
		}
		
		return std::move(*this).add_headers(headers_string);
	}
	/*
		Adds headers to the request.
	*/
	[[nodiscard]]
	auto add_headers(std::initializer_list<Header const> const headers) && -> Request&& {
		return std::move(*this).add_headers(std::span{headers});
	}
	/*
		Adds headers to the request.
		This is a variadic template that can take any number of headers.
	*/
	template<IsHeader ... _Header>
	[[nodiscard]]
	auto add_headers(_Header&& ... p_headers) && -> Request&& {
		auto const headers = std::array{Header{p_headers}...};
		return std::move(*this).add_headers(std::span{headers});
	}
	/*
		Adds a single header to the request.
		Equivalent to add_headers with a single Header argument.
	*/
	[[nodiscard]]
	auto add_header(Header const& header) && -> Request&& {
		return std::move(*this).add_headers(((std::string{header.name} += ": ") += header.value));
	}

private:
	utils::DataVector _body;

public:
	template<utils::IsByte _Byte>
	[[nodiscard]]
	auto set_body(std::span<_Byte const> const body_data) && -> Request&& {
		_body.resize(body_data.size());
		if constexpr (std::same_as<_Byte, std::byte>) {
			std::ranges::copy(body_data, _body.begin());
		}
		else {
			std::ranges::copy(std::span{reinterpret_cast<std::byte const*>(body_data.data()), body_data.size()}, _body.begin());
		}
		return std::move(*this);
	}
	[[nodiscard]]
	auto set_body(std::string_view const body_data) && -> Request&& {
		return std::move(*this).set_body(utils::string_to_data<std::byte>(body_data));
	}
	[[nodiscard]]
	auto set_body(std::u8string_view const body_data) && -> Request&& {
		return std::move(*this).set_body(utils::string_to_data<std::byte>(body_data));
	}

private:
	RequestMethod _method;

	std::u8string _url;
	utils::SplitUrl<char8_t> _split_url;

	algorithms::ResponseCallbacks _callbacks;

public:
	[[nodiscard]]
	auto set_raw_progress_callback(std::function<void(ResponseProgressRaw&)> callback) && -> Request&& {
		_callbacks.handle_raw_progress = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	auto set_headers_callback(std::function<void(ResponseProgressHeaders&)> callback) && -> Request&& {
		_callbacks.handle_headers = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	auto set_body_progress_callback(std::function<void(ResponseProgressBody&)> callback) && -> Request&& {
		_callbacks.handle_body_progress = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	auto set_finish_callback(std::function<void(Response&)> callback) && -> Request&& {
		_callbacks.handle_finish = std::move(callback);
		return std::move(*this);
	}

private:
	[[nodiscard]]
	auto send_and_get_receive_socket() -> Socket {
		auto socket = open_socket(_split_url.domain_name, utils::get_port(_split_url.protocol));
		
		using namespace std::string_view_literals;
		using namespace std::string_literals;

		if (!_body.empty()) {
			// TODO: Use std::format when available
			((((_headers += "Transfer-Encoding: identity"sv) += "\r\n"sv) +=
				"Content-Length: "sv) += std::to_string(_body.size())) += "\r\n"sv;
		}
		
		auto const request_data = utils::concatenate_byte_data(
			request_method_to_string(_method),
			' ',
			utils::u8string_to_utf8_string(_split_url.path),
			" HTTP/1.1\r\nHost: "sv,
			utils::u8string_to_utf8_string(_split_url.domain_name),
			_headers,
			"\r\n"sv,
			_body
		);
		socket.write(request_data);

		return socket;
	}

public:
	/*
		Sends the request and blocks until the response has been received.
	*/
	[[nodiscard]]
	auto send() && -> Response {
		return algorithms::receive_response(send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}
	/*
		Sends the request and returns immediately after the data has been sent.
		The returned future receives the response asynchronously.
	*/
	auto send_async() && -> std::future<Response> {
		return std::async(&algorithms::receive_response, send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}

	Request() = delete;
	~Request() = default;

	Request(Request&&) noexcept = default;
	auto operator=(Request&&) noexcept -> Request& = default;

	Request(Request const&) = delete;
	auto operator=(Request const&) -> Request& = delete;

private:
	Request(RequestMethod const method, std::u8string_view const url, Protocol const default_protocol) :
		_method{method},
		_url{utils::uri_encode(url)},
		_split_url{utils::split_url(std::u8string_view{_url})}
	{
		if (_split_url.protocol == Protocol::Unknown) {
			_split_url.protocol = default_protocol;
		}
	}
	friend auto get(std::u8string_view, Protocol) -> Request;
	friend auto post(std::u8string_view, Protocol) -> Request;
	friend auto put(std::u8string_view, Protocol) -> Request;
	friend auto make_request(RequestMethod, std::u8string_view, Protocol) -> Request;
};

/*
	Creates a GET request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]] 
inline auto get(std::u8string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return Request{RequestMethod::Get, url, default_protocol};
}
/*
	Creates a GET request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]] 
inline auto get(std::string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return get(utils::utf8_string_to_u8string(url), default_protocol);
}

/*
	Creates a POST request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto post(std::u8string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return Request{RequestMethod::Post, url, default_protocol};
}
/*
	Creates a POST request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto post(std::string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return post(utils::utf8_string_to_u8string(url), default_protocol);
}

/*
	Creates a PUT request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto put(std::u8string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return Request{RequestMethod::Put, url, default_protocol};
}
/*
	Creates a PUT request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto put(std::string_view const url, Protocol const default_protocol = Protocol::Http) -> Request {
	return put(utils::utf8_string_to_u8string(url), default_protocol);
}

/*
	Creates a http request.
	Can be used to do the same things as http::get and http::post, but with more method options.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto make_request(
	RequestMethod const method, 
	std::u8string_view const url, 
	Protocol const default_protocol = Protocol::Http
) -> Request {
	return Request{method, url, default_protocol};
}

/*
	Creates a http request.
	Can be used to do the same things as http::get and http::post, but with more method options.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline auto make_request(
	RequestMethod const method, 
	std::string_view const url, 
	Protocol const default_protocol = Protocol::Http
) -> Request {
	return make_request(method, utils::utf8_string_to_u8string(url), default_protocol);
}

} // namespace http

} // namespace internet_client
