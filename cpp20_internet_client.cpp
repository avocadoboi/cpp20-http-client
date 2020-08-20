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

#include "cpp20_internet_client.hpp"

//---------------------------------------------------------

#include <span>
#include <array>
#include <system_error>

//---------------------------------------------------------

#ifdef _WIN32
#include <windows.h>

#include <WinInet.h>
#endif

//---------------------------------------------------------

namespace internet_client {

// Platform-specific utilities
namespace utils {

#ifdef _WIN32
namespace win {

auto utf8_to_wide(std::u8string_view const p_input) -> std::wstring {
	auto result = std::wstring(MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(p_input.data()), static_cast<int>(p_input.size()), 
		0, 0
	), '\0');

	MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(p_input.data()), static_cast<int>(p_input.size()), 
		result.data(), static_cast<int>(result.size())
	);

	return result;
}

auto utf8_to_wide(std::u8string_view const p_input, std::span<wchar_t> p_output) {
	auto const length = MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(p_input.data()), static_cast<int>(p_input.size()), 
		p_output.data(), static_cast<int>(p_output.size())
	);

	if (length > 0) {
		p_output[length] = 0;
	}
}

auto wide_to_utf8(std::wstring_view const p_input) -> std::u8string {
	auto result = std::u8string(WideCharToMultiByte(
		CP_UTF8, 0, 
		p_input.data(), static_cast<int>(p_input.size()), 
		0, 0, nullptr, nullptr
	), '\0');

	WideCharToMultiByte(
		CP_UTF8, 0, 
		p_input.data(), static_cast<int>(p_input.size()), 
		reinterpret_cast<char*>(result.data()), static_cast<int>(result.size()),
		nullptr, nullptr
	);

	return result;
}

auto wide_to_utf8(std::wstring_view const p_input, std::span<char8_t> p_output) {
	auto const length = WideCharToMultiByte(
		CP_UTF8, 0, 
		p_input.data(), static_cast<int>(p_input.size()), 
		reinterpret_cast<char*>(p_output.data()), static_cast<int>(p_output.size()),
		nullptr, nullptr
	);

	if (length > 0) {
		p_output[length] = 0;
	}
}

//---------------------------------------------------------

auto throw_error(
	std::string p_reason, 
	int const error_code = static_cast<int>(GetLastError())
) -> void 
{
	p_reason += " with code ";
	p_reason += std::to_string(error_code);
	throw std::system_error{error_code, std::system_category(), p_reason};
}

} // namespace win
#endif // _WIN32

} // namespace utils

namespace http {

#ifdef _WIN32
class InternetHandle {
private:
	HINTERNET m_handle{};
public:
	operator HINTERNET() const noexcept {
		return m_handle;
	}

private:
	auto close() {
		if (m_handle) {
			InternetCloseHandle(m_handle);
		}
	}

	auto handle_creation_errors() {
		if (!m_handle) {
			switch (auto const error_code = GetLastError()) {
				case ERROR_INTERNET_INVALID_URL:
				case ERROR_INVALID_NAME:
					throw errors::InvalidUrl{};
				case ERROR_INTERNET_ITEM_NOT_FOUND:
					throw errors::ItemNotFound{};
				case ERROR_INTERNET_TIMEOUT:
					throw errors::ConnectionFailed::Timeout;
				case ERROR_INTERNET_SHUTDOWN:
					throw errors::ConnectionFailed::Shutdown;
				default:
					utils::win::throw_error("Creating HINTERNET failed", error_code);
			}
		}
	}
	
public:
	~InternetHandle() {
		close();
	}

	InternetHandle() = default;
	InternetHandle(HINTERNET const p_handle) :
		m_handle{p_handle}
	{
		handle_creation_errors();
	}
	auto operator=(HINTERNET const p_internet_handle) -> auto& {
		close();
		m_handle = p_internet_handle;
		handle_creation_errors();
		return *this;
	}

	InternetHandle(InternetHandle const&) = delete;
	auto operator=(InternetHandle const&) -> auto& = delete;

	InternetHandle(InternetHandle&& p_other) :
		m_handle{p_other.m_handle}
	{
		p_other.m_handle = nullptr;
	}
	auto operator=(InternetHandle&& p_other) -> auto& {
		close();
		m_handle = p_other.m_handle;
		p_other.m_handle = nullptr;
		return *this;
	}
};

//---------------------------------------------------------

struct HttpConnectionHandles {
	InternetHandle
		internet_open,
		internet_connect,
		open_request;
};

class GetResponse::Implementation {
private:
	HttpConnectionHandles m_connection;

	std::optional<std::vector<std::byte>> m_body;
	
	[[nodiscard]]
	auto get_available_data_size() -> DWORD {
		auto available_size = DWORD{};
		if (!InternetQueryDataAvailable(m_connection.open_request, &available_size, 0, 0)) {
			utils::win::throw_error("Failed to query the size of the packet.");
		}
		return available_size;
	}

	struct PacketReadResult {
		DWORD bytes_read;
		bool succeeded;
	};
	[[nodiscard]]
	auto read_packet(std::span<std::byte> const p_buffer) const -> PacketReadResult {
		auto result = PacketReadResult{};
		result.succeeded = InternetReadFile(
			m_connection.open_request, 
			p_buffer.data(), p_buffer.size(), 
			&result.bytes_read
		);
		return result;
	}
	
	auto read_response_body() -> void {
		if (m_body) {
			return;
		}

		auto available_size = get_available_data_size();
		m_body = std::vector<std::byte>(available_size);

		auto read_offset = size_t{};
		while (true) {
			auto const [bytes_read, succeeded] = read_packet({m_body->data() + read_offset, available_size});

			if (available_size = get_available_data_size()) {
				read_offset += bytes_read;
				m_body->resize(read_offset + available_size);
			}
			else if (succeeded)
			{
				break;
			}
		}
	}
public:
	[[nodiscard]]
	auto get_body() -> std::span<std::byte> {
		if (!m_body) {
			read_response_body();
		}
		return *m_body;
	}

private:
	std::optional<std::string> m_headers_string;

	[[nodiscard]]
	auto query_response_info_string(int const p_info_flag) -> std::string {
		auto const throw_error = [](int const error_code) {
			utils::win::throw_error("Failed to retrieve response info string", error_code);
		};

		auto buffer_byte_count = DWORD{};
		auto const try_buffer = [&](auto&& buffer) -> std::optional<std::string> {
			if (HttpQueryInfoA(m_connection.open_request, p_info_flag, buffer.data(), &buffer_byte_count, 0)) {
				return std::string{buffer.data(), buffer_byte_count};
			}
			return {};
		};

		constexpr auto static_buffer_size = 256;
		buffer_byte_count = static_buffer_size;
		if (auto const result = try_buffer(std::array<char, static_buffer_size>())) {
			return *result;
		} else if (auto const error_code = GetLastError(); error_code == ERROR_INSUFFICIENT_BUFFER) {
			if (auto const result = try_buffer(std::vector<char>(buffer_byte_count))) {
				return *result;
			}
			else throw_error(GetLastError());
		} else throw_error(error_code);

		// This technically can't happen but compilers warn if we don't return in every path.
		return {};
	}
	auto query_headers_string() -> void {
		m_headers_string = query_response_info_string(HTTP_QUERY_RAW_HEADERS_CRLF);
	}
	
public:
	[[nodiscard]]
	auto get_headers_string() -> std::string_view {
		if (!m_headers_string) {
			query_headers_string();
		}
		return *m_headers_string;
	}
	
private:
	std::optional<std::vector<Header>> m_parsed_headers;
	auto parse_headers() -> void {
		if (!m_headers_string) {
			query_headers_string();
		}
		m_parsed_headers = algorithms::parse_headers_string(*m_headers_string);
	}
public:
	[[nodiscard]]
	auto get_headers() -> std::span<Header> {
		if (!m_parsed_headers) {
			parse_headers();
		}
		return *m_parsed_headers;
	}

private:
	[[nodiscard]]
	auto find_header(std::string_view const p_name) 
		-> std::optional<std::vector<Header>::iterator>
	{
		if (!m_parsed_headers) {
			parse_headers();
		}

		auto const lowercase_name_to_search = utils::range_to_string(p_name | utils::ascii_lowercase_transform);
		return utils::find_if(*m_parsed_headers, [&](auto const& header) {
			return std::ranges::equal(lowercase_name_to_search, header.name | utils::ascii_lowercase_transform);
		});
	}

public:
	[[nodiscard]]
	auto get_header(std::string_view const p_name) -> std::optional<Header> {
		if (auto const pos = find_header(p_name)) {
			return **pos;
		}
		else {
			return {};
		}
	}
	[[nodiscard]]
	auto get_header_value(std::string_view const p_name) -> std::optional<std::string_view> {
		if (auto const pos = find_header(p_name)) {
			return (*pos)->value;
		}
		else {
			return {};
		}
	}

public:
	Implementation(HttpConnectionHandles&& p_connection) : 
		m_connection{std::move(p_connection)}
	{}
};
#endif // _WIN32

GetResponse::GetResponse(std::unique_ptr<Implementation> p_implementation) :
	m_implementation{std::move(p_implementation)}
{}

GetResponse::GetResponse(GetResponse&&) = default;
auto GetResponse::operator=(GetResponse&&) -> GetResponse& = default;

GetResponse::~GetResponse() = default;

auto GetResponse::get_headers() const -> std::span<Header> {
	return m_implementation->get_headers();
}
auto GetResponse::get_headers_string() const -> std::string_view {
	return m_implementation->get_headers_string();
}

auto GetResponse::get_header(std::string_view p_header_name) const -> std::optional<Header> {
	return m_implementation->get_header(p_header_name);
}
auto GetResponse::get_header_value(std::string_view p_header_name) const -> std::optional<std::string_view> {
	return m_implementation->get_header_value(p_header_name);
}

auto GetResponse::get_body() const -> std::span<std::byte> {
	return m_implementation->get_body();
}

//---------------------------------------------------------

#ifdef _WIN32
class GetRequest::Implementation {
private:
	std::string m_user_agent = std::string{GetRequest::default_user_agent};
public:
	auto set_user_agent(std::string_view const p_user_agent) -> void {
		m_user_agent = p_user_agent;
	}

	//---------------------------------------------------------

private:		
	std::string m_headers;
public:
	auto add_headers(std::string_view const p_headers) -> void {
		if (p_headers.empty()) {
			return;
		}
		m_headers += p_headers;
		if (p_headers.back() != '\n') {
			m_headers += "\r\n"; // CRLF is the correct line ending for the HTTP protocol
		}
	}

	//---------------------------------------------------------

private:
	HttpConnectionHandles m_connection;

	// not wstring_view because null termination is required
	auto open_connection(std::wstring const p_domain_name) -> void {
		m_connection.internet_open = InternetOpenA(
			m_user_agent.data(), 
			INTERNET_OPEN_TYPE_DIRECT, 
			nullptr, nullptr, 
			0
		);
		m_connection.internet_connect = InternetConnectW(
			m_connection.internet_open, 
			p_domain_name.data(),
			INTERNET_DEFAULT_HTTP_PORT, 
			nullptr, nullptr, 
			INTERNET_SERVICE_HTTP, 
			0, 0
		);
	}
	
	auto open_request(std::wstring const p_object_path) -> void {
		auto accepted_types = std::array{L"*", static_cast<LPCWSTR>(nullptr)};
		
		m_connection.open_request = HttpOpenRequestW(
			m_connection.internet_connect,
			L"GET",
			p_object_path.empty() ? nullptr : p_object_path.data(), // required to add null terminator
			nullptr,
			nullptr,
			accepted_types.data(),
			0, 0
		);
	}

	auto send_request() -> void {
		if (!HttpSendRequestA(
			m_connection.open_request,
			m_headers.data(),
			static_cast<DWORD>(m_headers.size()),
			nullptr, 0
		)) {
			switch (auto const error_code = GetLastError()) {
				case ERROR_INTERNET_NAME_NOT_RESOLVED:
					throw errors::ConnectionFailed::NoInternet;
				default:
					utils::win::throw_error("Failed sending http request", error_code);
			}
		}
	}

public:
	[[nodiscard]]
	auto send() -> GetResponse {
		auto const [domain_name, object_path] = utils::split_url(std::wstring_view{m_url});
		
		open_connection(std::wstring{domain_name});
		open_request(std::wstring{object_path});
		send_request();

		return std::make_unique<GetResponse::Implementation>(std::move(m_connection));
	}

	//---------------------------------------------------------

private:
	std::wstring m_url;
public:
	Implementation(std::u8string_view const p_url) :
		m_url{utils::win::utf8_to_wide(p_url)} 
	{}
};
#endif // _WIN32

//---------------------------------------------------------

GetRequest::GetRequest(GetRequest&&) = default;
auto GetRequest::operator=(GetRequest&&) -> GetRequest& = default;

GetRequest::~GetRequest() = default;

auto GetRequest::set_user_agent(std::string_view const p_user_agent) && -> GetRequest&& {
	m_implementation->set_user_agent(p_user_agent);
	return std::move(*this);
}

auto GetRequest::add_headers(std::string_view const p_headers) && -> GetRequest&& {
	m_implementation->add_headers(p_headers);
	return std::move(*this);
}

auto GetRequest::send() && -> GetResponse {
	return m_implementation->send();
}

GetRequest::GetRequest(std::u8string_view const p_url) :
	m_implementation{std::make_unique<Implementation>(p_url)} 
{}

} // namespace http

} // namespace internet_client
