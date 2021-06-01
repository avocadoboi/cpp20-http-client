/*
MIT License

Copyright (c) 2021 Björn Sundin

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
	An enumeration of the transfer protocols that are supported by the library.
*/
enum class Protocol : Port {
	Http = 80,
	Https = 443,
	Unknown = -1, 
};

/*
	This is everything that doesn't have anything to do with the core functionality, 
	but are utilities that are used within the library.
*/
namespace utils {

/*
	This is a concept for IsAnyOf<T, U, V, W, ...> where T is equal to any of U, V, W, ...
*/
template<typename T, typename ... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

//---------------------------------------------------------

template<typename T>
concept IsTrivial = std::is_trivial_v<T>;

template<typename T>
concept IsByte = sizeof(T) == 1 && IsTrivial<std::remove_reference_t<T>>;

//---------------------------------------------------------

/*
	Used to invoke a lambda at the end of a scope.
*/
template<std::invocable T>
class [[nodiscard]] Cleanup {
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
	Cleanup& operator=(Cleanup&&) noexcept = delete;

	Cleanup(Cleanup const&) = delete;
	Cleanup& operator=(Cleanup const&) = delete;
	
private:
	T _callable;
};

//---------------------------------------------------------

/*
	Similar to std::unique_ptr except that non-pointer types can be held
	and that a custom deleter must be specified. 

	This is useful for OS handles that are integer types, for example a native socket handle.
	Use C++20 lambdas in unevaluated contexts to specify a deleter, or use an already defined 
	functor type. 
	
	Example:
	using DllHandle = utils::UniqueHandle<HMODULE, decltype([](auto& h){ FreeLibrary(h); })>;
*/
template<IsTrivial T, std::invocable<T&> Deleter_, T invalid_handle = T{}>
class UniqueHandle {
public:
	[[nodiscard]]
	constexpr explicit operator T() const noexcept {
		return _handle;
	}
	[[nodiscard]]
	constexpr T get() const noexcept {
		return _handle;
	}
	[[nodiscard]]
	constexpr T& get() noexcept {
		return _handle;
	}

	[[nodiscard]]
	constexpr T const* operator->() const noexcept {
		return &_handle;
	}
	[[nodiscard]]
	constexpr T* operator->() noexcept {
		return &_handle;
	}

	[[nodiscard]]
	constexpr T const* operator&() const noexcept {
		return &_handle;
	}
	[[nodiscard]]
	constexpr T* operator&() noexcept {
		return &_handle;
	}

	[[nodiscard]]
	constexpr explicit operator bool() const noexcept {
		return _handle != invalid_handle;
	}
	[[nodiscard]]
	constexpr bool operator!() const noexcept {
		return _handle == invalid_handle;
	}

	[[nodiscard]]
	constexpr bool operator==(UniqueHandle const&) const noexcept 
		requires std::equality_comparable<T> 
		= default;

	constexpr explicit UniqueHandle(T const handle) :
		_handle{handle}
	{}
	constexpr UniqueHandle& operator=(T const handle) {
		_close();
		_handle = handle;
		return *this;
	}

	constexpr UniqueHandle() = default;
	constexpr ~UniqueHandle() {
		_close();
	}

	constexpr UniqueHandle(UniqueHandle&& handle) noexcept :
		_handle{handle._handle}
	{
		handle._handle = invalid_handle;
	}
	constexpr UniqueHandle& operator=(UniqueHandle&& handle) noexcept {
		_handle = handle._handle;
		handle._handle = invalid_handle;
		return *this;
	}

	constexpr UniqueHandle(UniqueHandle const&) = delete;
	constexpr UniqueHandle& operator=(UniqueHandle const&) = delete;

private:
	T _handle{invalid_handle};

	constexpr void _close() {
		if (_handle != invalid_handle) {
			Deleter_{}(_handle);
			_handle = invalid_handle;
		}
	}
};

//---------------------------------------------------------

/*
	This can be called when the program reaches a path that should never be reachable.
	It prints error output and exits the program.
*/
#ifdef __cpp_lib_source_location
[[noreturn]]
inline void unreachable(std::source_location const& source_location = std::source_location::current()) {
	// TODO: use std::format when supported
	// std::cerr << std::format("Reached an unreachable code path in file {}, in function {}, on line {}.", 
	// 	source_location.file_name(), source_location.function_name(), source_location.line());
	std::cerr << "Reached an unreachable code path in file " << source_location.file_name() << 
		", in function " << source_location.function_name() << ", on line " << source_location.line() << ".\n";
	std::exit(1);
}
#else
[[noreturn]]
inline void unreachable() {
	std::cerr << "Reached an unreachable code path, exiting.\n";
	std::exit(1);
}
#endif

/*
	Prints an error message to the error output stream and exits the program.
*/
[[noreturn]]
inline void panic(std::string_view const message) {
	std::cerr << message << '\n';
	std::exit(1);
}

//---------------------------------------------------------

template<typename Range_, typename ValueType_>
concept IsInputRangeOf = std::ranges::input_range<Range_> && std::same_as<std::ranges::range_value_t<Range_>, ValueType_>;

template<typename Range_, typename ValueType_>
concept IsSizedRangeOf = IsInputRangeOf<Range_, ValueType_> && std::ranges::sized_range<Range_>;

/*
	Converts a range of contiguous characters to a std::basic_string_view.
*/
constexpr auto range_to_string_view = []<
	/* 
		std::views::split returns a range of ranges.
		The ranges unfortunately are not std::ranges::contiguous_range
		even when the base type is contiguous, so we can't use that constraint.
	*/
	IsInputRangeOf<char> Range_
> (Range_&& range) {
	return std::string_view{
		&*std::ranges::begin(range), 
		static_cast<std::string_view::size_type>(std::ranges::distance(range))
	};
};

//---------------------------------------------------------

void enable_utf8_console();

//---------------------------------------------------------

/*
	Copies a sized range to a std::basic_string of any type.
*/
template<IsSizedRangeOf<char> Range_> 
[[nodiscard]]
inline std::string range_to_string(Range_ const& range) {
	auto result = std::string(range.size(), char{});
	std::ranges::copy(range, std::ranges::begin(result));
	return result;
}

/*
	Copies a range of unknown size to a std::basic_string of any type.
*/
template<IsInputRangeOf<char> Range_> 
[[nodiscard]]
inline std::string range_to_string(Range_ const& range) {
	auto result = std::string();
	std::ranges::copy(range, std::back_inserter(result));
	return result;
}

/*
	Reinterprets a span of any byte-sized trivial type as a string view of a specified byte-sized character type.
*/
template<IsByte Byte_>
[[nodiscard]] 
std::string_view data_to_string(std::span<Byte_> const data) {
	return std::string_view{reinterpret_cast<char const*>(data.data()), data.size()};
}
/*
	Reinterprets a string view of any byte-sized character type as a span of any byte-sized trivial type.
*/
template<IsByte Byte_>
[[nodiscard]]
std::span<Byte_ const> string_to_data(std::string_view const string) {
	return std::span{reinterpret_cast<Byte_ const*>(string.data()), string.size()};
}

//---------------------------------------------------------

using DataVector = std::vector<std::byte>;

//---------------------------------------------------------

template<std::movable T>
void append_to_vector(std::vector<T>& vector, std::span<T const> const data) {
	vector.insert(vector.end(), data.begin(), data.end());
}

//---------------------------------------------------------

template<typename T>
concept IsByteData = IsByte<T> || std::ranges::range<T> && IsByte<std::ranges::range_value_t<T>>;

/*
	Returns the size of any trivial byte-sized element or range of trivial byte-sized elements.
*/
template<IsByteData T>
[[nodiscard]]
std::size_t size_of_byte_data(T&& data) {
	if constexpr (std::ranges::range<T>) {
		return std::ranges::distance(data);
	}
	else {
		return sizeof(data);
	}
}

/*
	Copies any type of trivial byte-sized element(s) from data to range.
*/
template<IsByteData Data_, std::ranges::contiguous_range Range_, IsByte RangeValue_ = std::ranges::range_value_t<Range_>> 
[[nodiscard]]
auto copy_byte_data(Data_&& data, Range_&& range) 
	-> std::ranges::iterator_t<Range_> 
{
	if constexpr (IsByte<Data_>) {
		*std::ranges::begin(range) = *reinterpret_cast<RangeValue_*>(&data);
		return std::ranges::begin(range) + 1;
	}
	else {
		return std::ranges::copy(std::span{
			reinterpret_cast<RangeValue_ const*>(std::ranges::data(data)), 
			std::ranges::size(data)
		}, std::ranges::begin(range)).out;
	}
}

/*
	Concatenates any kind of sequence of trivial byte-sized elements like char and std::byte.
	The arguments can be individual bytes and/or ranges of bytes.
	Returns a utils::DataVector (std::vector<std::byte>).
*/
template<IsByteData ... T>
[[nodiscard]]
DataVector concatenate_byte_data(T&& ... arguments) {
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
std::optional<T> string_to_integral(std::string_view const string, int const base = 10) 
{
	auto number_result = T{};
	auto const char_pointer = string.data();
	if (std::from_chars(char_pointer, char_pointer + string.size(), number_result, base).ec == std::errc{}) {
		return number_result;
	}
	return {};
}

//---------------------------------------------------------

template<std::ranges::contiguous_range DataRange_> requires IsByte<std::ranges::range_value_t<DataRange_>>
void write_to_file(DataRange_ const& data, std::string const& file_name) {
	// std::string because std::ofstream does not take std::string_view.
	auto file_stream = std::ofstream{file_name, std::ios::binary};
	file_stream.write(reinterpret_cast<char const*>(std::ranges::data(data)), std::ranges::size(data));
}

//---------------------------------------------------------

constexpr auto filter_true = std::views::filter([](auto const& x){ return static_cast<bool>(x); });
constexpr auto dereference_move = std::views::transform([](auto&& x) { return std::move(*x); });

/*
	Transforms a range of chars into its lowercase equivalent.
*/
constexpr auto ascii_lowercase_transform = std::views::transform([](char const c) { 
	return static_cast<char>(std::tolower(c));
});

/*
	Returns whether lhs and rhs are equal, regardless of casing, assuming both are encoded in ASCII.
*/
[[nodiscard]]
constexpr bool equal_ascii_case_insensitive(std::string_view const lhs, std::string_view const rhs) noexcept {
	return std::ranges::equal(lhs | ascii_lowercase_transform, rhs | ascii_lowercase_transform);
}

//---------------------------------------------------------

/*
	Returns the port that corresponds to the specified protocol.
*/
[[nodiscard]]
constexpr Port get_port(Protocol const protocol) noexcept {
	return static_cast<Port>(protocol);
}

/*
	Returns the protocol that corresponds to the specified case-insensitive string.
	For example, "http" converts to Protocol::Http.
*/
[[nodiscard]]
constexpr Protocol get_protocol_from_string(std::string_view const protocol_string) noexcept {
	if (equal_ascii_case_insensitive(protocol_string, "http")) {
		return Protocol::Http;
	}
	else if (equal_ascii_case_insensitive(protocol_string, "https")) {
		return Protocol::Https;
	}
	return Protocol::Unknown;
}

/*
	The result of the split_url function.
*/
struct SplitUrl {
	Protocol protocol{Protocol::Unknown};
	std::string_view domain_name, path;
};

/*
	Splits an URL into a server/domain name and file path.
*/
[[nodiscard]] 
inline SplitUrl split_url(std::string_view const url) noexcept {
	using namespace std::string_view_literals;
	
	if (url.empty()) {
		return {};
	}

	constexpr auto whitespace_characters = " \t\r\n"sv;
	auto start_position = url.find_first_not_of(whitespace_characters);
	if (start_position == std::string_view::npos) {
		return {};
	}
	
	auto result = SplitUrl{};

	constexpr auto protocol_suffix = "://"sv;
	if (auto const position = url.find(protocol_suffix, start_position);
		position != std::string_view::npos) 
	{
		result.protocol = get_protocol_from_string(url.substr(start_position, position - start_position));
		start_position = position + protocol_suffix.length();
	}

	if (auto const position = url.find('/', start_position);
		position != std::string_view::npos)
	{
		result.domain_name = url.substr(start_position, position - start_position);
		start_position = position;
	}
	else {
		result.domain_name = url.substr(start_position);
		result.path = "/"sv;
		return result;
	}

	auto const end_position = url.find_last_not_of(whitespace_characters) + 1;
	result.path = url.substr(start_position, end_position - start_position);
	return result;
}

/*
	Returns the file name part of a URL (or file path with only forward slashes).
*/
[[nodiscard]]
constexpr std::string_view extract_filename(std::string_view const url) 
{
	if (auto const slash_pos = url.rfind('/');
		slash_pos != std::string_view::npos)
	{
		if (auto const question_mark_pos = url.find('?', slash_pos + 1);
			question_mark_pos != std::string_view::npos)
		{
			return url.substr(slash_pos + 1, question_mark_pos - slash_pos - 1);
		}

		return url.substr(slash_pos + 1);
	}
	return {};
}

/*
	Returns whether character is allowed in a URI-encoded string or not.
*/
[[nodiscard]]
constexpr bool get_is_allowed_uri_character(char const character) noexcept {
	constexpr auto other_characters = std::string_view{"%-._~:/?#[]@!$&'()*+,;="};
	
	return character >= '0' && character <= '9' || 
		character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		other_characters.find(character) != std::string_view::npos;
}

/*
	Returns the URI-encoded equivalent of uri.
*/
[[nodiscard]]
inline std::string uri_encode(std::string_view const uri) {
	auto result_string = std::string();
	result_string.reserve(uri.size());

	for (auto const character : uri) {
		if (get_is_allowed_uri_character(character)) {
			result_string += character;
		}
		else {
			result_string += "%xx";
			std::to_chars(
				&result_string.back() - 1, 
				&result_string.back() + 1, 
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
public:
	[[nodiscard]]
	char const* what() const noexcept override {
		return _reason.c_str();
	}

	[[nodiscard]]
	bool get_is_tls_failure() const noexcept {
		return _is_tls_failure;
	}

	ConnectionFailed(std::string reason, bool const is_tls_failure = false) noexcept :
		_reason(std::move(reason)),
		_is_tls_failure{is_tls_failure}
	{}

private:
	std::string _reason;
	bool _is_tls_failure;
};

class ResponseParsingFailed : public std::exception {
public:
	[[nodiscard]]
	char const* what() const noexcept override {
		return _reason.c_str();
	}

	ResponseParsingFailed(std::string reason) :
		_reason(std::move(reason))
	{}

private:
	std::string _reason;
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
	void write(std::span<std::byte const> data) const;
	/*
		Sends a string to the peer through the socket.
		This function takes a basic_string_view, think about 
		whether you want it to be null terminated or not.
	*/
	void write(std::string_view const string_view) const {
		write(utils::string_to_data<std::byte const>(string_view));
	}

	/*
		Receives data from the socket and reads it into a buffer.
		This function blocks until there is some data available.
		The data that was read may be smaller than the buffer.
		The function either returns the number of bytes that were read 
		or a ConnectionClosed value if the peer closed the connection. 
	*/
	[[nodiscard("The result is important as it contains the size that was actually read.")]]
	std::variant<ConnectionClosed, std::size_t> read(std::span<std::byte> buffer) const;
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
	std::variant<ConnectionClosed, std::size_t> read_available(std::span<std::byte> buffer) const;
	/*
		Reads any available data from the socket into a buffer.
		This function is nonblocking, and may return an empty vector if 
		there was no data available. The function either returns a utils::DataVector 
		of the data that was read or a ConnectionClosed value if the peer 
		closed the connection.
	*/
	template<std::size_t read_buffer_size = 512>
	[[nodiscard]]
	std::variant<ConnectionClosed, utils::DataVector> read_available() const {
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
	Socket& operator=(Socket&&) noexcept; // = default in .cpp
 
	Socket(Socket const&) = delete;
	Socket& operator=(Socket const&) = delete;

private:
	class Implementation;
	std::unique_ptr<Implementation> _implementation;
	
	Socket(std::string_view server, Port port, bool is_tls_encrypted);
	friend Socket open_socket(std::string_view, Port, bool);
};

/*
	Opens a socket to a server through a port.
	If port is 443 OR is_tls_encrypted is true, TLS encryption is used. 
	Otherwise it is unencrypted.
*/
[[nodiscard]]
inline Socket open_socket(std::string_view const server, Port const port, bool const is_tls_encrypted = false) {
	return Socket{server, port, is_tls_encrypted};
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
bool operator==(IsHeader auto const& lhs, IsHeader auto const& rhs) {
	return lhs.value == rhs.value && utils::equal_ascii_case_insensitive(lhs.name, rhs.name);
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
	bool operator==(StatusLine const&) const noexcept = default;
};

namespace algorithms {

[[nodiscard]]
inline StatusLine parse_status_line(std::string_view const line) {
	auto status_line = StatusLine{};

	auto cursor = std::size_t{};
	
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
constexpr std::optional<Header> parse_header(std::string_view const line) {
	/*
		"An HTTP header consists of its case-insensitive name followed by a colon (:), 
		then by its value. Whitespace before the value is ignored." 
		(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

		So we're just ignoring whitespace before the value, and after because there may be
		an \r there if the line endings are CRLF.
	*/

	auto const colon_pos = line.find(':');
	if (colon_pos == std::string_view::npos) {
		return {};
	}
	
	constexpr auto whitespace_characters = std::string_view{" \t\r"};
	
	auto const value_start = line.find_first_not_of(whitespace_characters, colon_pos + 1);
	if (value_start == std::string_view::npos) {
		return {};
	}
	
	// This will never be npos, assuming the header 
	// string isn't mutated by some other thread.
	auto const value_end = line.find_last_not_of(whitespace_characters);
	
	return Header{
		.name = line.substr(0, colon_pos), 
		.value = line.substr(value_start, value_end + 1 - value_start)
	};
}

[[nodiscard]] 
inline std::vector<Header> parse_headers_string(std::string_view const headers) 
{
	auto result = std::vector<Header>();

	std::ranges::copy(
		headers 
		| std::views::split('\n') | std::views::transform(utils::range_to_string_view)
		| std::views::transform(parse_header) | utils::filter_true | utils::dereference_move,
		std::back_inserter(result)
	);

	return result;
}

template<std::ranges::input_range Range_, IsHeader Header_ = std::ranges::range_value_t<Range_>>
[[nodiscard]]
inline Header_ const* find_header_by_name(Range_ const& headers, std::string_view const name) 
{
	auto const lowercase_name_to_search = utils::range_to_string(
		name | utils::ascii_lowercase_transform
	);
	auto const pos = std::ranges::find_if(headers, [&](Header_ const& header) {
		return std::ranges::equal(lowercase_name_to_search, header.name | utils::ascii_lowercase_transform);
	});
	if (pos == std::ranges::end(headers)) {
		return nullptr;
	}
	else {
		return &*pos;
	}
}

struct ParsedResponse {
	StatusLine status_line;
	std::string headers_string;
	std::vector<Header> headers; // Points into headers_string
	utils::DataVector body_data;

	[[nodiscard]]
	bool operator==(ParsedResponse const&) const noexcept = default;
};

struct ParsedHeadersInterface {
	constexpr virtual ParsedResponse const& get_parsed_response() const noexcept = 0;

	/*
		Returns the status code from the response header.
	*/
	[[nodiscard]]
	StatusCode get_status_code() const {
		return get_parsed_response().status_line.status_code;
	}
	/*
		Returns the status code description from the response header.
	*/
	[[nodiscard]]
	std::string_view get_status_message() const {
		return get_parsed_response().status_line.status_message;
	}
	/*
		Returns the HTTP version from the response header.
	*/
	[[nodiscard]]
	std::string_view get_http_version() const {
		return get_parsed_response().status_line.http_version;
	}
	/*
		Returns a const reference to the parsed status line object.
	*/
	[[nodiscard]]
	StatusLine const& get_status_line() const {
		return get_parsed_response().status_line;
	}

	/*
		Returns the headers of the response as a string.
		The returned string_view shall not outlive this Response object.
	*/
	[[nodiscard]] 
	std::string_view get_headers_string() const {
		return get_parsed_response().headers_string;
	}

	/*
		Returns the headers of the response as Header objects.
		The returned span shall not outlive this Response object.
	*/
	[[nodiscard]] 
	std::span<Header const> get_headers() const {
		return get_parsed_response().headers;
	}
	/*
		Returns a header of the response by its name.
		The returned header shall not outlive this Response object.
	*/	
	[[nodiscard]] 
	std::optional<Header> get_header(std::string_view const name) const {
		if (auto const header = algorithms::find_header_by_name(get_parsed_response().headers, name)) {
			return *header;
		}
		else return {};
	}
	/*
		Returns a header value of the response by its name.
		The returned std::string_view shall not outlive this Response object.
	*/
	[[nodiscard]] 
	std::optional<std::string_view> get_header_value(std::string_view const name) const {
		if (auto const header = algorithms::find_header_by_name(get_parsed_response().headers, name)) {
			return header->value;
		}
		else return {};
	}
};

class ResponseParser;

} // namespace algorithms

class ResponseProgressRaw {	
	friend class algorithms::ResponseParser;
	
public:
	constexpr void stop() noexcept {
		_is_stopped = true;
	}

	std::span<std::byte const> data;
	std::size_t new_data_start;

	explicit constexpr ResponseProgressRaw(std::span<std::byte const> const p_data, std::size_t const p_new_data_start) noexcept :
		data{p_data}, new_data_start{p_new_data_start}
	{}

private:
	bool _is_stopped{false};
};

class ResponseProgressHeaders : public algorithms::ParsedHeadersInterface {
public:
	ResponseProgressRaw raw_progress;

	constexpr void stop() noexcept {
		raw_progress.stop();
	}
	
	[[nodiscard]]
	constexpr algorithms::ParsedResponse const& get_parsed_response() const noexcept override {
		return _parsed_response;
	}

	ResponseProgressHeaders(ResponseProgressRaw const p_raw_progress, algorithms::ParsedResponse const& parsed_response) :
		raw_progress{p_raw_progress}, _parsed_response{parsed_response}
	{}

	ResponseProgressHeaders() = delete;
	~ResponseProgressHeaders() = default;
	
	ResponseProgressHeaders(ResponseProgressHeaders const&) = delete;
	ResponseProgressHeaders& operator=(ResponseProgressHeaders const&) = delete;

	ResponseProgressHeaders(ResponseProgressHeaders&&) noexcept = delete;
	ResponseProgressHeaders& operator=(ResponseProgressHeaders&&) noexcept = delete;

private:
	algorithms::ParsedResponse const& _parsed_response;
};

class ResponseProgressBody : public algorithms::ParsedHeadersInterface {
public:
	ResponseProgressRaw raw_progress;

	std::span<std::byte const> body_data_so_far;
	/*
		This may not have a value if the transfer encoding is chunked, in which
		case the full body length is not known ahead of time.
	*/
	std::optional<std::size_t> total_expected_body_size;

	constexpr void stop() noexcept {
		raw_progress.stop();
	}
	
	[[nodiscard]]
	constexpr algorithms::ParsedResponse const& get_parsed_response() const noexcept override {
		return _parsed_response;
	}

	ResponseProgressBody(
		ResponseProgressRaw const p_raw_progress, 
		algorithms::ParsedResponse const& parsed_response,
		std::span<std::byte const> const p_body_data_so_far, 
		std::optional<std::size_t> const p_total_expected_body_size
	) : 
		raw_progress{p_raw_progress},
		body_data_so_far{p_body_data_so_far},
		total_expected_body_size{p_total_expected_body_size},
		_parsed_response{parsed_response}
	{}

	ResponseProgressBody() = delete;
	~ResponseProgressBody() = default;
	
	ResponseProgressBody(ResponseProgressBody const&) = delete;
	ResponseProgressBody& operator=(ResponseProgressBody const&) = delete;

	ResponseProgressBody(ResponseProgressBody&&) noexcept = delete;
	ResponseProgressBody& operator=(ResponseProgressBody&&) noexcept = delete;

private:
	algorithms::ParsedResponse const& _parsed_response;
};

/*
	Represents the response of a HTTP request.
*/
class Response : public algorithms::ParsedHeadersInterface {
public:
	[[nodiscard]]
	constexpr algorithms::ParsedResponse const& get_parsed_response() const noexcept override {
		return _parsed_response;
	}
	
	/*
		Returns the body of the response.
		The returned std::span shall not outlive this Response object.
	*/
	[[nodiscard]]
	std::span<std::byte const> get_body() const {
		return _parsed_response.body_data;
	}
	/*
		Returns the body of the response as a string.
		The returned std::string_view shall not outlive this Response object.
	*/
	[[nodiscard]] 
	std::string_view get_body_string() const {
		return utils::data_to_string(get_body());
	}

	[[nodiscard]]
	std::string_view get_url() const {
		return _url;
	}

	Response() = delete;
	~Response() = default;

	Response(Response const&) = delete;
	Response& operator=(Response const&) = delete;
	
	Response(Response&&) noexcept = default;
	Response& operator=(Response&&) noexcept = default;

	Response(algorithms::ParsedResponse&& parsed_response, std::string&& url) :
		_parsed_response{std::move(parsed_response)},
		_url{std::move(url)}
	{}

private:
	algorithms::ParsedResponse _parsed_response;
	std::string _url;
};

namespace algorithms {

class ChunkyBodyParser {
public:
	[[nodiscard]]
	std::optional<utils::DataVector> parse_new_data(std::span<std::byte const> const new_data) {
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
			if (auto const cursor_offset = _parse_next_part(new_data.subspan(cursor))) {
				cursor += cursor_offset;
			}
			else {
				_has_returned_result = true;
				return std::move(_result);
			}
		}
	}
	[[nodiscard]]
	std::span<std::byte const> get_result_so_far() const {
		return _result;
	}

private:
	static constexpr auto newline = std::string_view{"\r\n"};

	/*
		"part" refers to a separately parsed unit of data.
		This paritioning makes the parsing algorithm simpler.
		Returns the position where the part ended.
		It may be past the end of the part.
	*/
	[[nodiscard]]
	std::size_t _parse_next_part(std::span<std::byte const> const new_data) {
		if (_chunk_size_left) {
			return _parse_chunk_body_part(new_data);
		}
		else return _parse_chunk_separator_part(new_data);
	}

	[[nodiscard]]
	std::size_t _parse_chunk_body_part(std::span<std::byte const> const new_data) {
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

	[[nodiscard]]
	std::size_t _parse_chunk_separator_part(std::span<std::byte const> const new_data) {
		auto const data_string = utils::data_to_string(new_data);

		auto const first_newline_character_pos = data_string.find(newline[0]);
		
		if (first_newline_character_pos == std::string_view::npos) {
			_chunk_size_string_buffer += data_string;
			return new_data.size();
		}
		else if (_chunk_size_string_buffer.empty()) {
			_parse_chunk_size_left(data_string.substr(0, first_newline_character_pos));
		}
		else {
			_chunk_size_string_buffer += data_string.substr(0, first_newline_character_pos);
			_parse_chunk_size_left(_chunk_size_string_buffer);
			_chunk_size_string_buffer.clear();
		}

		if (_chunk_size_left == 0) {
			_is_finished = true;
			return 0;
		}
		
		return first_newline_character_pos + newline.size();
	}

	void _parse_chunk_size_left(std::string_view const string) {
		// hexadecimal
		if (auto const result = utils::string_to_integral<std::size_t>(string, 16)) {
			_chunk_size_left = *result;
		}
		else throw errors::ResponseParsingFailed{"Failed parsing http body chunk size."};
	}
	
	utils::DataVector _result;

	bool _is_finished{false};
	bool _has_returned_result{false};

	std::size_t _start_parse_offset{};
	
	std::string _chunk_size_string_buffer;
	std::size_t _chunk_size_left{};
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
public:
	/*
		Parses a new packet of data from the HTTP response.
		If it reached the end of the response, the parsed result is returned.
	*/
	[[nodiscard]]
	std::optional<ParsedResponse> parse_new_data(std::span<std::byte const> const data) {
		if (_is_done) {
			return {};
		}
		
		auto const new_data_start = _buffer.size();
		
		utils::append_to_vector(_buffer, data);

		if (_callbacks && (*_callbacks)->handle_raw_progress) {
			auto raw_progress = ResponseProgressRaw{_buffer, new_data_start};
			(*_callbacks)->handle_raw_progress(raw_progress);
			if (raw_progress._is_stopped) {
				_finish();
			}
		}
		
		if (!_is_done && _result.headers_string.empty()) {
			_try_parse_headers(new_data_start);
		}

		if (!_is_done && !_result.headers_string.empty()) {
			if (_chunky_body_parser) {
				_parse_new_chunky_body_data(new_data_start);
			}
			else {
				_parse_new_regular_body_data(new_data_start);
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
	
private:
	void _finish() {
		_is_done = true;
		if (_callbacks && (*_callbacks)->handle_stop) {
			(*_callbacks)->handle_stop();
		}
	}

	void _try_parse_headers(std::size_t const new_data_start) {
		if (auto const headers_string = _try_extract_headers_string(new_data_start))
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
					_finish();
				}
			}

			if (auto const body_size_try = _get_body_size()) {
				_body_size = *body_size_try;
			}
			else if (auto const transfer_encoding = algorithms::find_header_by_name(_result.headers, "transfer-encoding");
				transfer_encoding && transfer_encoding->value == "chunked")
			{
				_chunky_body_parser = ChunkyBodyParser{};
			}
		}
	}
	[[nodiscard]]
	std::optional<std::string_view> _try_extract_headers_string(std::size_t const new_data_start) {
		// '\n' line endings are not conformant with the HTTP standard.
		for (std::string_view const empty_line : {"\r\n\r\n", "\n\n"})
		{
			auto const find_start = static_cast<std::size_t>(std::max(std::int64_t{}, 
				static_cast<std::int64_t>(new_data_start - empty_line.length() + 1)
			));
			
			auto const string_view_to_search = utils::data_to_string(std::span{_buffer});

			if (auto const position = string_view_to_search.find(empty_line, find_start);
				position != std::string_view::npos) 
			{
				_body_start = position + empty_line.length();
				return string_view_to_search.substr(0, position);
			}
		}
		return {};
	}
	[[nodiscard]]
	std::optional<std::size_t> _get_body_size() const {
		if (auto const content_length_string = 
				algorithms::find_header_by_name(_result.headers, "content-length")) 
		{
			if (auto const parse_result = 
					utils::string_to_integral<std::size_t>(content_length_string->value)) 
			{
				return *parse_result;
			}
		}
		return {};
	}

	void _parse_new_chunky_body_data(std::size_t const new_data_start) {
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
			
			_finish();
		}
		else if (_callbacks && (*_callbacks)->handle_body_progress) {
			auto body_progress = ResponseProgressBody{
				ResponseProgressRaw{_buffer, new_data_start}, 
				_result, 
				_chunky_body_parser->get_result_so_far(), {}
			};
			(*_callbacks)->handle_body_progress(body_progress);
			if (body_progress.raw_progress._is_stopped) {
				_finish();
			}
		}
	}

	void _parse_new_regular_body_data(std::size_t const new_data_start) {
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

			_finish();
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
				_finish();
			}
		}
	}

	utils::DataVector _buffer;

	ParsedResponse _result;
	bool _is_done{false};

	std::size_t _body_start{};
	std::size_t _body_size{};

	std::optional<ChunkyBodyParser> _chunky_body_parser;

	std::optional<ResponseCallbacks*> _callbacks;
};

template<std::size_t buffer_size = std::size_t{1} << 12>
[[nodiscard]]
inline Response receive_response(Socket const&& socket, std::string&& url, ResponseCallbacks&& callbacks) {
	auto has_stopped = false;
	callbacks.handle_stop = [&has_stopped]{ has_stopped = true; };
	
	auto response_parser = algorithms::ResponseParser{callbacks};

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

/*
	Enumeration of the different HTTP request methods that can be used.
*/
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

/*
	Converts a RequestMethod to its uppercase string equivalent.
	For example, RequestMethod::Get becomes std::string_view{"GET"}.
*/
[[nodiscard]]
inline std::string_view request_method_to_string(RequestMethod const method) {
	using enum RequestMethod;
	switch (method) {
		case Connect: return "CONNECT";
		case Delete:  return "DELETE";
		case Get:     return "GET";
		case Head:    return "HEAD";
		case Options: return "OPTIONS";
		case Patch:   return "PATCH";
		case Post:    return "POST";
		case Put:     return "PUT";
		case Trace:   return "TRACE";
	}
	utils::unreachable();
}

/*
	Represents a HTTP request.
	It is created by calling any of the HTTP verb functions (http::get, http::post, http::put ...)
*/
class Request {
public:
	/*
		Adds headers to the request as a string.
		These are in the format: "NAME: [ignored whitespace] VALUE"
		The string can be multiple lines for multiple headers.
		Non-ASCII bytes are considered opaque data,
		according to the HTTP specification.
	*/
	[[nodiscard]]
	Request&& add_headers(std::string_view const headers_string) && {
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
	template<IsHeader Header_, std::size_t extent = std::dynamic_extent>
	[[nodiscard]]
	Request&& add_headers(std::span<Header_ const, extent> const headers) && {
		auto headers_string = std::string{};
		headers_string.reserve(headers.size()*128);
		
		for (auto const& header : headers) {
			(((headers_string += header.name) += ": ") += header.value) += "\r\n";
		}
		
		return std::move(*this).add_headers(headers_string);
	}
	/*
		Adds headers to the request.
	*/
	[[nodiscard]]
	Request&& add_headers(std::initializer_list<Header const> const headers) && {
		return std::move(*this).add_headers(std::span{headers});
	}
	/*
		Adds headers to the request.
		This is a variadic template that can take any number of headers.
	*/
	template<IsHeader ... Header_>
	[[nodiscard]]
	Request&& add_headers(Header_&& ... p_headers) && {
		auto const headers = std::array{Header{p_headers}...};
		return std::move(*this).add_headers(std::span{headers});
	}
	/*
		Adds a single header to the request.
		Equivalent to add_headers with a single Header argument.
	*/
	[[nodiscard]]
	Request&& add_header(Header const& header) && {
		return std::move(*this).add_headers(((std::string{header.name} += ": ") += header.value));
	}

	/*
		Sets the content of the request as a sequence of bytes.
	*/
	template<utils::IsByte Byte_>
	[[nodiscard]]
	Request&& set_body(std::span<Byte_ const> const body_data) && {
		_body.resize(body_data.size());
		if constexpr (std::same_as<Byte_, std::byte>) {
			std::ranges::copy(body_data, _body.begin());
		}
		else {
			std::ranges::copy(std::span{reinterpret_cast<std::byte const*>(body_data.data()), body_data.size()}, _body.begin());
		}
		return std::move(*this);
	}
	/*
		Sets the content of the request as a string view.
	*/
	[[nodiscard]]
	Request&& set_body(std::string_view const body_data) && {
		return std::move(*this).set_body(utils::string_to_data<std::byte>(body_data));
	}

	[[nodiscard]]
	Request&& set_raw_progress_callback(std::function<void(ResponseProgressRaw&)> callback) && {
		_callbacks.handle_raw_progress = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	Request&& set_headers_callback(std::function<void(ResponseProgressHeaders&)> callback) && {
		_callbacks.handle_headers = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	Request&& set_body_progress_callback(std::function<void(ResponseProgressBody&)> callback) && {
		_callbacks.handle_body_progress = std::move(callback);
		return std::move(*this);
	}
	[[nodiscard]]
	Request&& set_finish_callback(std::function<void(Response&)> callback) && {
		_callbacks.handle_finish = std::move(callback);
		return std::move(*this);
	}

	// Note: send and send_async are not [[nodiscard]] because callbacks 
	// could potentially be used exclusively to handle the response.

	/*
		Sends the request and blocks until the response has been received.
	*/
	Response send() && {
		return algorithms::receive_response<>(_send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}
	/*
		Sends the request and blocks until the response has been received.

		The buffer_size template parameter specifies the size of the buffer that data
		from the server is read into at a time. If it is small, then data will be received
		in many times in smaller pieces, with some time cost. If it is big, then 
		data will be read few times but in large pieces, with more memory cost.
	*/
	template<std::size_t buffer_size>
	Response send() && {
		return algorithms::receive_response<buffer_size>(_send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}
	/*
		Sends the request and returns immediately after the data has been sent.
		The returned future receives the response asynchronously.
	*/
	std::future<Response> send_async() && {
		return std::async(&algorithms::receive_response<>, _send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}
	/*
		Sends the request and returns immediately after the data has been sent.
		The returned future receives the response asynchronously.

		The buffer_size template parameter specifies the size of the buffer that data
		from the server is read into at a time. If it is small, then data will be received
		in many times in smaller pieces, with some time cost. If it is big, then 
		data will be read few times but in large pieces, with more memory cost.
	*/
	template<std::size_t buffer_size>
	std::future<Response> send_async() && {
		return std::async(&algorithms::receive_response<buffer_size>, _send_and_get_receive_socket(), std::move(_url), std::move(_callbacks));
	}

	Request() = delete;
	~Request() = default;

	Request(Request&&) noexcept = default;
	Request& operator=(Request&&) noexcept = default;

	Request(Request const&) = delete;
	Request& operator=(Request const&) = delete;

private:
	[[nodiscard]]
	Socket _send_and_get_receive_socket() {
		auto socket = open_socket(_split_url.domain_name, utils::get_port(_split_url.protocol));
		
		using namespace std::string_view_literals;

		if (!_body.empty()) {
			// TODO: Use std::format when available
			// _headers += std::format("Transfer-Encoding: identity\r\nContent-Length: {}\r\n", _body.size());
			((_headers += "Transfer-Encoding: identity\r\nContent-Length: ") += std::to_string(_body.size())) += "\r\n";
		}
		
		auto const request_data = utils::concatenate_byte_data(
			request_method_to_string(_method),
			' ',
			_split_url.path,
			" HTTP/1.1\r\nHost: "sv,
			_split_url.domain_name,
			_headers,
			"\r\n"sv,
			_body
		);
		socket.write(request_data);

		return socket;
	}

	RequestMethod _method;

	std::string _url;
	utils::SplitUrl _split_url;

	std::string _headers{"\r\n"};
	utils::DataVector _body;

	algorithms::ResponseCallbacks _callbacks;

	Request(RequestMethod const method, std::string_view const url, Protocol const default_protocol) :
		_method{method},
		_url{utils::uri_encode(url)},
		_split_url{utils::split_url(std::string_view{_url})}
	{
		if (_split_url.protocol == Protocol::Unknown) {
			_split_url.protocol = default_protocol;
		}
	}
	friend Request get(std::string_view, Protocol);
	friend Request post(std::string_view, Protocol);
	friend Request put(std::string_view, Protocol);
	friend Request make_request(RequestMethod, std::string_view, Protocol);
};

/*
	Creates a GET request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]] 
inline Request get(std::string_view const url, Protocol const default_protocol = Protocol::Http) {
	return Request{RequestMethod::Get, url, default_protocol};
}

/*
	Creates a POST request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline Request post(std::string_view const url, Protocol const default_protocol = Protocol::Http) {
	return Request{RequestMethod::Post, url, default_protocol};
}

/*
	Creates a PUT request.
	url is a URL to the server or resource that the request targets.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline Request put(std::string_view const url, Protocol const default_protocol = Protocol::Http) {
	return Request{RequestMethod::Put, url, default_protocol};
}

/*
	Creates a http request.
	Can be used to do the same things as http::get and http::post, but with more method options.
	If url contains a protocol prefix, it is used. Otherwise, default_protocol is used.
*/
[[nodiscard]]
inline Request make_request(
	RequestMethod const method, 
	std::string_view const url, 
	Protocol const default_protocol = Protocol::Http
) {
	return Request{method, url, default_protocol};
}

} // namespace http

} // namespace internet_client
