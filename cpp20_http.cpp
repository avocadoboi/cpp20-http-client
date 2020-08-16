#include "cpp20_http.hpp"

//---------------------------------------------------------

#include <span>
#include <array>
#include <system_error>

// Debugging
#include <iostream>

//---------------------------------------------------------

#ifdef _WIN32
#include <windows.h>

#include <WinInet.h>
// #pragma comment(lib, "Wininet")
#endif

//---------------------------------------------------------

namespace http {

// Platform-specific utilities
namespace util {

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

} // namespace util

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
					throw error::InvalidUrl{};
				case ERROR_INTERNET_ITEM_NOT_FOUND:
					throw error::ItemNotFound{};
				case ERROR_INTERNET_TIMEOUT:
					throw error::ConnectionFailed::Timeout;
				case ERROR_INTERNET_SHUTDOWN:
					throw error::ConnectionFailed::Shutdown;
				default:
					util::win::throw_error("Creating HINTERNET failed", error_code);
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
		internet_open_handle,
		internet_connect_handle,
		open_request_handle;
};

class GetResponse::Implementation {
private:
	HttpConnectionHandles m_connection;

	std::optional<std::vector<std::byte>> mutable m_content;
	
	[[nodiscard]]
	auto get_available_data_size() const -> DWORD {
		auto available_size = DWORD{};
		if (!InternetQueryDataAvailable(m_connection.open_request_handle, &available_size, 0, 0)) {
			util::win::throw_error("Failed to query the size of the packet.");
		}
		return available_size;
	}
	auto read_response_content() const -> void {
		if (m_content) {
			return;
		}

		auto available_size = get_available_data_size();
		m_content = std::vector<std::byte>(available_size);
		auto read_offset = size_t{};
		while (true) {
			auto number_of_bytes_read = DWORD{};
			auto const succeeded = InternetReadFile(
				m_connection.open_request_handle, 
				m_content->data() + read_offset, 
				available_size, 
				&number_of_bytes_read
			);

			if (available_size = get_available_data_size()) {
				read_offset += number_of_bytes_read;
				m_content->resize(read_offset + available_size);
			}
			else if (succeeded)
			{
				break;
			}
		}
	}
public:
	[[nodiscard]]
	auto get_content_data() const -> std::span<std::byte> {
		if (!m_content) {
			read_response_content();
		}
		return *m_content;
	}

private:
	std::optional<std::u8string> mutable m_headers_string;

	[[nodiscard]]
	auto query_response_info_string(int p_info_flag) const -> std::u8string {
		auto const query_info = [&](wchar_t* const buffer, DWORD* const size) -> bool {
			return HttpQueryInfoW(
				m_connection.open_request_handle, 
				p_info_flag, 
				buffer, 
				size,
				0
			);
		};

		auto static_buffer = std::array<wchar_t, 256>();
		auto buffer_byte_count = static_cast<DWORD>(static_buffer.size()*sizeof(wchar_t));

		if (query_info(static_buffer.data(), &buffer_byte_count)) {
			return util::win::wide_to_utf8({static_buffer.data(), buffer_byte_count/sizeof(wchar_t)});
		}
		else
		{
			auto error_code = GetLastError();
			if (error_code == ERROR_INSUFFICIENT_BUFFER) {
				auto dynamic_buffer = std::vector<wchar_t>(buffer_byte_count/sizeof(wchar_t));
				if (query_info(dynamic_buffer.data(), &buffer_byte_count)) {
					return util::win::wide_to_utf8({dynamic_buffer.data(), buffer_byte_count/sizeof(wchar_t)});
				}
				else {
					error_code = GetLastError();
				}
			}
			util::win::throw_error("Failed to retrieve response info string", error_code);
		}
	}
	auto query_headers_string() const -> void {
		m_headers_string = query_response_info_string(HTTP_QUERY_RAW_HEADERS_CRLF);
	}
	
public:
	[[nodiscard]]
	auto get_headers_string() const -> std::u8string_view {
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
public:
	[[nodiscard]]
	auto get_headers() const -> std::span<Header> {
		if (!m_parsed_headers) {
			parse_headers();
		}
		return *m_parsed_headers;
	}

private:
	[[nodiscard]]
	auto find_header(std::u8string_view const p_name) const 
		-> std::optional<std::vector<Header>::iterator>
	{
		if (!m_parsed_headers) {
			parse_headers();
		}
		return util::find_if(*m_parsed_headers, [&](auto const& header) {
			return header.name == p_name; // TODO: handle case insensitivity.
		});
	}

public:
	[[nodiscard]]
	auto get_header(std::u8string_view const p_name) const -> std::optional<Header> {
		if (auto const pos = find_header(p_name)) {
			return **pos;
		}
		else {
			return {};
		}
	}
	[[nodiscard]]
	auto get_header_value(std::u8string_view const p_name) const -> std::optional<std::u8string_view> {
		if (auto const pos = find_header(p_name)) {
			return (*pos)->value;
		}
		else {
			return {};
		}
	}

	Implementation(HttpConnectionHandles&& p_connection) : 
		m_connection{std::move(p_connection)}
	{}
};
#endif // _WIN32

auto GetResponse::get_headers() const -> std::span<Header> {
	return m_implementation->get_headers();
}
auto GetResponse::get_headers_string() const -> std::u8string_view {
	return m_implementation->get_headers_string();
}

auto GetResponse::get_header(std::u8string_view p_header_name) const -> std::optional<Header> {
	return m_implementation->get_header(p_header_name);
}
auto GetResponse::get_header_value(std::u8string_view p_header_name) const -> std::optional<std::u8string_view> {
	return m_implementation->get_header_value(p_header_name);
}

auto GetResponse::get_content_data() const -> std::span<std::byte> {
	return m_implementation->get_content_data();
}

GetResponse::~GetResponse() = default;

GetResponse::GetResponse(std::unique_ptr<Implementation> p_implementation) :
	m_implementation{std::move(p_implementation)}
{}


//---------------------------------------------------------

#ifdef _WIN32
class GetRequest::Implementation {
private:
	std::wstring m_user_agent = L"Cpp20Http";
public:
	auto set_user_agent(std::u8string_view const p_user_agent) -> void {
		m_user_agent = util::win::utf8_to_wide(p_user_agent);
	}

	//---------------------------------------------------------

private:		
	std::wstring m_headers;
public:
	auto add_headers(std::u8string_view const p_headers) -> void {
		if (p_headers.empty()) {
			return;
		}
		m_headers += util::win::utf8_to_wide(p_headers);
		if (p_headers.back() != u8'\n') {
			m_headers += L"\r\n"; // CRLF is the correct line ending for the HTTP protocol
		}
	}

	//---------------------------------------------------------

private:
	HttpConnectionHandles m_connection;

	// not wstring_view because null termination is required
	auto open_connection(std::wstring const p_domain_name) -> void {
		m_connection.internet_open_handle = InternetOpenW(
			m_user_agent.data(), 
			INTERNET_OPEN_TYPE_DIRECT, 
			nullptr, nullptr, 
			0
		);
		m_connection.internet_connect_handle = InternetConnectW(
			m_connection.internet_open_handle, 
			p_domain_name.data(),
			INTERNET_DEFAULT_HTTP_PORT, 
			nullptr, nullptr, 
			INTERNET_SERVICE_HTTP, 
			0, 0
		);
	}
	
	auto open_request(std::wstring const p_object_path) -> void {
		auto accepted_types = std::array{L"*", static_cast<LPCWSTR>(nullptr)};
		
		m_connection.open_request_handle = HttpOpenRequestW(
			m_connection.internet_connect_handle,
			L"GET",
			p_object_path.empty() ? nullptr : p_object_path.data(), // required to add null terminator
			nullptr,
			nullptr,
			accepted_types.data(),
			0, 0
		);
	}

	auto send_request() -> void {
		if (!HttpSendRequestW(
			m_connection.open_request_handle,
			m_headers.data(),
			static_cast<DWORD>(m_headers.size()),
			nullptr, 0
		)) {
			switch (auto const error_code = GetLastError()) {
				case ERROR_INTERNET_NAME_NOT_RESOLVED:
					throw error::ConnectionFailed::NoInternet;
				default:
					util::win::throw_error("Failed sending http request", error_code);
			}
		}
	}

public:
	[[nodiscard]]
	auto send() -> GetResponse {
		auto const [domain_name, object_path] = algorithms::split_url(std::wstring_view{m_url});
		
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
		m_url{util::win::utf8_to_wide(p_url)} 
	{}
};
#endif // _WIN32

//---------------------------------------------------------

auto GetRequest::set_user_agent(std::u8string_view const p_user_agent) && -> GetRequest&& {
	m_implementation->set_user_agent(p_user_agent);
	return std::move(*this);
}

auto GetRequest::add_headers(std::u8string_view const p_headers) && -> GetRequest&& {
	m_implementation->add_headers(p_headers);
	return std::move(*this);
}

auto GetRequest::send() && -> GetResponse {
	return m_implementation->send();
}

GetRequest::GetRequest(std::u8string_view const p_url) :
	m_implementation{std::make_unique<Implementation>(p_url)} 
{}
GetRequest::~GetRequest() = default;

} // namespace http
