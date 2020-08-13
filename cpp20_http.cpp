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
#pragma comment(lib, "Wininet")
#endif

//---------------------------------------------------------

#ifdef _WIN32
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

auto utf8_to_wide(std::wstring_view const p_input, std::span<char8_t> p_output) {
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

auto throw_last_winapi_error(
	std::string p_reason, 
	int const error_code = static_cast<int>(GetLastError())
) -> void 
{
	p_reason += " with code ";
	p_reason += std::to_string(error_code);
	throw std::system_error{error_code, std::system_category(), p_reason};
}

#endif

//---------------------------------------------------------

namespace http {
#ifdef _WIN32
	class InternetHandle {
	private:
		HINTERNET m_handle{};

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
						throw error::ConnectionTimeout{};
					case ERROR_INTERNET_SHUTDOWN:
						throw error::ConnectionShutdown{};
					default:
						throw_last_winapi_error("Creating HINTERNET failed", error_code);
				}
			}
		}
		
	public:
		operator HINTERNET() const noexcept {
			return m_handle;
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

		~InternetHandle() {
			close();
		}
	};

	class GetRequest::Implementation {
	private:
		std::wstring m_url;

		//---------------------------------------------------------

		std::wstring m_user_agent = L"Cpp20Http";
	public:
		auto set_user_agent(std::u8string_view const p_user_agent) {
			m_user_agent = utf8_to_wide(p_user_agent);
		}

		//---------------------------------------------------------

	private:		
		std::wstring m_headers;
	public:
		auto set_headers(std::u8string_view const p_headers) {
			m_headers = utf8_to_wide(p_headers);	
		}

		//---------------------------------------------------------

	private:
		InternetHandle m_internet_open_handle;
		// InternetHandle m_url_handle;
		InternetHandle m_internet_connect_handle;
		InternetHandle m_open_request_handle;
	
		// null termination of the domain name is required
		auto open_connection(std::wstring const p_domain_name) {
			m_internet_open_handle = InternetOpenW(
				m_user_agent.data(), 
				INTERNET_OPEN_TYPE_DIRECT, 
				nullptr, nullptr, 
				0
			);

			// m_url_handle = InternetOpenUrlW(
			// 	m_internet_open_handle,
			// 	m_url.data(),
			// 	m_headers.data(),
			// 	m_headers.size(),
			// 	0, 0
			// );
			
			m_internet_connect_handle = InternetConnectW(
				m_internet_open_handle, 
				p_domain_name.data(),
				INTERNET_DEFAULT_HTTP_PORT, 
				nullptr, nullptr, 
				INTERNET_SERVICE_HTTP, 
				0, 0
			);
		}
		auto send_request() {
			auto [domain_name, object_path] = split_url(std::wstring_view{m_url});
			
			open_connection(std::wstring{domain_name});
			
			auto accepted_types = std::array{L"*", static_cast<LPCWSTR>(nullptr)};
			
			m_open_request_handle = HttpOpenRequestW(
				m_internet_connect_handle,
				L"GET",
				object_path.empty() ? nullptr : std::wstring{object_path}.data(), // required to add null terminator
				nullptr,
				nullptr,
				accepted_types.data(),
				0, 0
			);

			if (!HttpSendRequestW(
				m_open_request_handle,
				m_headers.data(),
				static_cast<DWORD>(m_headers.size()),
				nullptr, 0
			)) {
				// TODO: handle error code 12007: name not resolved
				throw_last_winapi_error("Failed sending http request");
			}
		}

		auto get_available_data_size() -> DWORD {
			auto available_size = DWORD{};
			if (!InternetQueryDataAvailable(m_open_request_handle, &available_size, 0, 0)) {
				throw_last_winapi_error("Failed to query the size of the available data to be retreived from the internet.");
			}
			return available_size;
		}

	public:
		auto send() -> GetResponse {
			send_request();

			// HttpQueryInfoW(internet_handle, )

			auto available_size = get_available_data_size();
			auto content = std::vector<std::byte>(available_size);
			auto read_offset = size_t{};
			while (true) {
				auto number_of_bytes_read = DWORD{};
				auto const succeeded = InternetReadFile(
					m_open_request_handle, 
					content.data() + read_offset, 
					available_size, 
					&number_of_bytes_read
				);

				if (available_size = get_available_data_size()) {
					read_offset += number_of_bytes_read;
					content.resize(read_offset + available_size);
				}
				else
				{
					break;
				}
			}

			return GetResponse{std::move(content)};
		}

		//---------------------------------------------------------

		Implementation(std::u8string_view const p_url) :
			m_url{utf8_to_wide(p_url)} 
		{}
	};
#endif

	//---------------------------------------------------------

	auto GetRequest::set_user_agent(std::u8string_view const p_user_agent) -> GetRequest& {
		m_implementation->set_user_agent(p_user_agent);
		return *this;
	}

	auto GetRequest::set_headers(std::u8string_view const p_headers) -> GetRequest& {
		m_implementation->set_headers(p_headers);
		return *this;
	}

	auto GetRequest::send() -> GetResponse {
		return m_implementation->send();
	}

	GetRequest::GetRequest(std::u8string_view const p_url) :
		m_implementation{std::make_unique<Implementation>(p_url)} 
	{}
	GetRequest::~GetRequest() = default;
}
