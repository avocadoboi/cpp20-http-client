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

#include <winsock2.h>
#include <ws2tcpip.h>

#endif

//---------------------------------------------------------

namespace internet_client {

// Platform-specific utilities
namespace utils {

#ifdef _WIN32
namespace win {

auto utf8_to_wide(std::u8string_view const input) -> std::wstring {
	auto result = std::wstring(MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(input.data()), static_cast<int>(input.size()), 
		0, 0
	), '\0');

	MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(input.data()), static_cast<int>(input.size()), 
		result.data(), static_cast<int>(result.size())
	);

	return result;
}

auto utf8_to_wide(std::u8string_view const input, std::span<wchar_t> output) {
	auto const length = MultiByteToWideChar(
		CP_UTF8, 0, 
		reinterpret_cast<char const*>(input.data()), static_cast<int>(input.size()), 
		output.data(), static_cast<int>(output.size())
	);

	if (length > 0) {
		output[length] = 0;
	}
}

auto wide_to_utf8(std::wstring_view const input) -> std::u8string {
	auto result = std::u8string(WideCharToMultiByte(
		CP_UTF8, 0, 
		input.data(), static_cast<int>(input.size()), 
		0, 0, nullptr, nullptr
	), '\0');

	WideCharToMultiByte(
		CP_UTF8, 0, 
		input.data(), static_cast<int>(input.size()), 
		reinterpret_cast<char*>(result.data()), static_cast<int>(result.size()),
		nullptr, nullptr
	);

	return result;
}

auto wide_to_utf8(std::wstring_view const input, std::span<char8_t> output) {
	auto const length = WideCharToMultiByte(
		CP_UTF8, 0, 
		input.data(), static_cast<int>(input.size()), 
		reinterpret_cast<char*>(output.data()), static_cast<int>(output.size()),
		nullptr, nullptr
	);

	if (length > 0) {
		output[length] = 0;
	}
}

//---------------------------------------------------------

auto throw_error(
	std::string reason, 
	int const error_code = static_cast<int>(GetLastError())
) -> void 
{
	reason += " with code ";
	reason += std::to_string(error_code);
	throw std::system_error{error_code, std::system_category(), reason};
}

} // namespace win
#endif // _WIN32

} // namespace utils

#ifdef _WIN32 

class WinSockLifetime {
public:
	WinSockLifetime(WinSockLifetime&&) = delete;
	auto operator=(WinSockLifetime&&) -> WinSockLifetime& = delete;
	WinSockLifetime(WinSockLifetime const&) = delete;
	auto operator=(WinSockLifetime const&) -> WinSockLifetime& = delete;

	WinSockLifetime() {
		auto api_info = WSADATA{};
		if (auto result = WSAStartup(MAKEWORD(2, 2), &api_info)) {
			utils::win::throw_error("Failed to initialize Winsock API 2.2", result);
		}
	}
	~WinSockLifetime() {
		WSACleanup();
	}
};

class SocketHandle {
private:
	SOCKET m_handle{INVALID_SOCKET};

	auto close() -> void {
		if (m_handle != INVALID_SOCKET) {
			closesocket(m_handle);
		}
	}
public:
	operator SOCKET() {
		return m_handle;
	}

	SocketHandle() = default;
	explicit SocketHandle(SOCKET handle) :
		m_handle{handle}
	{}
	~SocketHandle() {
		close();
	}

	auto operator=(SOCKET handle) -> SocketHandle& {
		close();
		m_handle = handle;
		return *this;
	}

	SocketHandle(SocketHandle const&) = delete;
	auto operator=(SocketHandle const&) -> SocketHandle& = delete;

	SocketHandle(SocketHandle&& handle) :
		m_handle{handle.m_handle} 
	{
		handle.m_handle = INVALID_SOCKET;
	} 
	auto operator=(SocketHandle&& handle) -> SocketHandle& {
		m_handle = handle.m_handle;
		handle.m_handle = INVALID_SOCKET;
		return *this;
	}
};

class Socket::Implementation {
public:
	auto send_data(std::span<std::byte> data) -> void {

	}
	auto send_string(std::u8string_view string) -> void {

	}
	
private:
	WinSockLifetime m_api_lifetime;
	
	SocketHandle m_handle;

	auto get_address_info(std::u8string_view const server, utils::Port const port) 
	{
		auto const wide_server_name = utils::win::utf8_to_wide(server);
		auto const wide_port_string = std::to_wstring(port);
		auto const hints = addrinfoW{
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
		};
		auto address_info = static_cast<addrinfoW*>(nullptr);

		while (auto const result = GetAddrInfoW(
			wide_server_name.data(), 
			wide_port_string.data(), 
			&hints, &address_info
		)) {
			if (result != EAI_AGAIN) {
				utils::win::throw_error("Failed to get address info for socket creation ", result);
			}
		}

		return std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>{address_info};
	}

	auto create_handle(std::u8string_view const server, utils::Port const port) -> SOCKET 
	{
		auto const address_info = get_address_info(server, port);
		
		constexpr auto milliseconds_to_wait_between_attempts = 1;

		auto socket_handle = SocketHandle{};
		while ((socket_handle = socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol)) == INVALID_SOCKET) 
		{
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::win::throw_error("Failed to create socket ", error_code);
			}
			Sleep(milliseconds_to_wait_between_attempts);
		}

		while (connect(socket_handle, address_info->ai_addr, static_cast<int>(address_info->ai_addrlen)) == SOCKET_ERROR)
		{
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::win::throw_error("Failed to connect socket ", error_code);
			}
			Sleep(milliseconds_to_wait_between_attempts);
		}

		return socket_handle;
	}

public:
	Implementation(std::u8string_view server, utils::Port port) :
		m_handle{create_handle(server, port)} 
	{}
};

#endif

auto Socket::send_data(std::span<std::byte> data) -> void {
	m_implementation->send_data(data);
}
auto Socket::send_string(std::u8string_view string) -> void {

}

auto Socket::receive_data() -> std::vector<std::byte> {
	return {};
}
auto Socket::receive_string() -> std::u8string {
	return {};
}

Socket::Socket(std::u8string_view server, utils::Port port) :
	m_implementation{std::make_unique<Implementation>(server, port)}
{}

Socket::Socket() = default;
Socket::Socket(Socket&&) = default;
auto Socket::operator=(Socket&&) -> Socket& = default;
Socket::~Socket() = default;

} // namespace internet_client
