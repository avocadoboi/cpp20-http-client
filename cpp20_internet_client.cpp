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

// debugging
#include <iostream>

//---------------------------------------------------------

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#endif

//---------------------------------------------------------

namespace internet_client {

// Platform-specific utilities
namespace utils {

auto enable_utf8_console() -> void {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif
}

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

	auto close() const -> void {
		if (m_handle != INVALID_SOCKET) {
			closesocket(m_handle);
		}
	}
public:
	explicit operator SOCKET() const {
		return m_handle;
	}
	auto get() const -> SOCKET {
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
private:
	WinSockLifetime m_api_lifetime;
	
	SocketHandle m_handle;

	static auto get_address_info(std::u8string_view const server, utils::Port const port) 
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
			if (result == EAI_AGAIN) {
				continue;
			}
			else if (result == WSAHOST_NOT_FOUND) {
				throw errors::ServerNotFound{};
			}
			else {
				utils::win::throw_error("Failed to get address info for socket creation", result);
			}
		}

		return std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>{address_info};
	}

	static auto create_handle(std::u8string_view const server, utils::Port const port) -> SocketHandle 
	{
		auto const address_info = get_address_info(server, port);
		
		auto const handle_error = [](auto error_message) {
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::win::throw_error(error_message, error_code);
			}
			constexpr auto milliseconds_to_wait_between_attempts = 1;
			Sleep(milliseconds_to_wait_between_attempts);
		};

		auto socket_handle = SocketHandle{};
		while ((socket_handle = socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol)).get() == INVALID_SOCKET) 
		{
			handle_error("Failed to create socket");
		}

		while (connect(socket_handle.get(), address_info->ai_addr, static_cast<int>(address_info->ai_addrlen)) == SOCKET_ERROR)
		{
			handle_error("Failed to connect socket");
		}

		return socket_handle;
	}

public:
	auto send_data(std::span<std::byte const> const data) -> void {
		auto const bytes_sent = send(
			m_handle.get(), 
			reinterpret_cast<char const*>(data.data()), 
			static_cast<int>(data.size()), 
			0
		);
		if (bytes_sent == SOCKET_ERROR) {
			utils::win::throw_error("Failed to send data through socket", WSAGetLastError());
		}
		if (shutdown(m_handle.get(), SD_SEND) == SOCKET_ERROR) {
			utils::win::throw_error("Failed to shut down socket connection after sending data", WSAGetLastError());
		}
	}
	auto send_string(std::u8string_view const string) -> void {
		send_data({reinterpret_cast<std::byte const*>(string.data()), string.length()});
	}

private:
	template<utils::IsAnyOf<std::vector<std::byte>, std::u8string> T>
	auto receive_to_container() const -> T {
		constexpr auto packet_size = 512;
		
		auto buffer = T();
		auto buffer_offset = 0ull;
		
		while (true) {
			buffer.resize(buffer_offset + packet_size);
			if (auto const result = recv(m_handle.get(), reinterpret_cast<char*>(buffer.data() + buffer_offset), static_cast<int>(packet_size), 0); 
				result > 0) 
			{
				buffer_offset += result;
			} 
			else if (result < 0) {
				utils::win::throw_error("Failed to receive data through socket", WSAGetLastError());
			}
			else break;
		}

		buffer.resize(buffer_offset);

		return buffer;
	}

public:
	auto receive_data() const -> std::vector<std::byte> {
		return receive_to_container<std::vector<std::byte>>();
	}
	auto receive_string() const -> std::u8string {
		return receive_to_container<std::u8string>();
	}

	auto receive_packet(std::span<std::byte> packet) const -> size_t {
		auto const result = recv(m_handle.get(), reinterpret_cast<char*>(packet.data()), packet.size(), 0);
		if (result < 0) {
			utils::win::throw_error("Failed to receive packet through socket", WSAGetLastError());
		}
		return result;
	}
	
public:
	Implementation(std::u8string_view const server, utils::Port const port) :
		m_handle{create_handle(server, port)} 
	{}
};

#endif

auto Socket::send_data(std::span<std::byte const> const data) const -> void {
	m_implementation->send_data(data);
}
auto Socket::send_string(std::u8string_view const string) const -> void {
	m_implementation->send_string(string);
}

auto Socket::receive_data() const -> std::vector<std::byte> {
	return m_implementation->receive_data();
}
auto Socket::receive_string() const -> std::u8string {
	return m_implementation->receive_string();
}
auto Socket::receive_packet(std::span<std::byte> packet) const -> size_t {
	return m_implementation->receive_packet(packet);
}

Socket::Socket(std::u8string_view const server, utils::Port const port) :
	m_implementation{std::make_unique<Implementation>(server, port)}
{}

Socket::Socket() = default;

Socket::Socket(Socket&&) = default;
auto Socket::operator=(Socket&&) -> Socket& = default;

Socket::~Socket() = default;

} // namespace internet_client
