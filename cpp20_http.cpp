#include "cpp20_http.hpp"

//---------------------------------------------------------

#include <string>
#include <span>
#include <array>

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
#endif

//---------------------------------------------------------

namespace http {
#ifdef _WIN32
	class InternetHandle {
	private:
		HINTERNET m_handle;

		auto close() {
			if (m_handle) {
				InternetCloseHandle(m_handle);
			}
		}
		
	public:
		operator HINTERNET() noexcept const {
			return m_handle;
		}
		
		InternetHandle(InternetHandle const&) = delete;
		InternetHandle(InternetHandle&& p_other) :
			m_handle{p_other.m_handle}
		{
			p_other.m_handle = nullptr;
		}
	
		auto operator=(InternetHandle const&) -> auto& = delete;
		auto operator=(InternetHandle&& p_other) -> auto& {
			close();
			m_handle = p_other.m_handle;
			p_other.m_handle = nullptr;
			return *this;
		}
	
		InternetHandle(HINTERNET const p_handle) :
			m_handle{p_handle}
		{
			if (!p_handle) {
				auto const error_code = static_cast<int>(GetLastError());
				throw std::system_error{error_code, std::system_category(), u8"Creating HINTERNET failed: " + error_code};
			}
		}
		~InternetHandle() {
			close();
		}
	};

	class GetRequest::Implementation {
	private:
		std::wstring m_url;

		//---------------------------------------------------------

		std::wstring m_user_agent;
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
		auto open_connection() -> InternetHandle {
			auto const internet_open_handle = InternetHandle{InternetOpenW(
				m_user_agent.data(), 
				INTERNET_OPEN_TYPE_DIRECT, 
				nullptr, nullptr, 
				INTERNET_FLAG_ASYNC
			)};
			return InternetHandle{InternetConnectW(
				internet_open_handle, 
				m_url.data(), 
				INTERNET_DEFAULT_HTTPS_PORT, 
				nullptr, nullptr, 
				INTERNET_SERVICE_HTTP, 
				0, 0
			)};
		}

	public:
		auto send() -> GetResponse {
			auto internet_handle = open_connection();
			
			auto accepted_types = std::array{L"*", static_cast<LPCWSTR>(nullptr)};
			
			internet_handle = HttpOpenRequestW(
				internet_handle,
				L"GET",
				m_url.data(),
				nullptr,
				nullptr,
				accepted_types.data(),
				0, 0
			);

			auto const succeeded = HttpSendRequestW(
				internet_handle,
				m_headers.data(),
				static_cast<DWORD>(m_headers.size()),
				nullptr, 0
			);
			if (!succeeded) {
				// TODO: add error handling
			}

			HttpQueryInfoW(internet_handle, )

			return {};
		}

		//---------------------------------------------------------

		Implementation(std::u8string_view const p_url) :
			m_url{utf8_to_wide(p_url)} 
		{}
		~Implementation() {

		}
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
