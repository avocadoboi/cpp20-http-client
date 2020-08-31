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

#include <variant>
#include <span>
#include <array>
#include <system_error>

// debugging
#include <iostream>

//---------------------------------------------------------

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#elif __has_include(<unistd.h>) // This header must exist on platforms that conform to the POSIX specifications

// The POSIX library is available on this platform.
#define IS_POSIX

#include <openssl/ssl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

// Name clash
#ifdef unix
#undef unix
#endif

#endif

//---------------------------------------------------------

namespace internet_client {

// Platform-specific utilities
namespace utils {

auto enable_utf8_console() -> void {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif
	// Pretty much everyone else uses utf-8 by default.
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

#ifdef IS_POSIX

namespace unix {

auto throw_error(
	std::string reason, 
	int const error_code = errno
) -> void 
{
	reason += " with code ";
	reason += std::to_string(error_code);
	throw std::system_error{error_code, std::generic_category(), reason};
}

} // namespace unix

#endif // IS_POSIX

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
				throw errors::ConnectionFailed{};
			}
			else {
				utils::win::throw_error("Failed to get address info for socket creation", result);
			}
		}

		return std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>{address_info};
	}

	static auto create_handle(std::u8string_view const server, utils::Port const port) -> SocketHandle {
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

	auto receive_response() const -> SocketResponse {
		constexpr auto packet_size = 512;
		
		auto buffer = std::vector<std::byte>(packet_size);
		auto buffer_offset = 0ull;
		
		while (true) {
			if (auto const result = recv(m_handle.get(), reinterpret_cast<char*>(buffer.data() + buffer_offset), static_cast<int>(packet_size), 0); 
				result > 0) 
			{
				buffer_offset += result;
				buffer.resize(buffer_offset + packet_size);
			} 
			else if (result < 0) {
				utils::win::throw_error("Failed to receive data through socket");
			}
			else break;
		}

		return SocketResponse{.data=std::move(buffer)};
	}

public:
	auto send(std::span<std::byte const> const data) const -> SocketResponse {
		if (::send(
			m_handle.get(), 
			reinterpret_cast<char const*>(data.data()), 
			static_cast<int>(data.size()), 
			0
		) == SOCKET_ERROR) {
			utils::win::throw_error("Failed to send data through socket", WSAGetLastError());
		}
		if (shutdown(m_handle.get(), SD_SEND) == SOCKET_ERROR) {
			utils::win::throw_error("Failed to shut down socket connection after sending data", WSAGetLastError());
		}
		return receive_response();
	}
	
	Implementation(std::u8string_view const server, utils::Port const port) :
		m_handle{create_handle(server, port)} 
	{}
};

#endif // _WIN32

#ifdef IS_POSIX

using PosixSocketHandle = int;

class SocketHandle {
private:
	constexpr static auto invalid_handle = -1;

	PosixSocketHandle m_handle{invalid_handle};

	auto close() const -> void {
		if (m_handle != invalid_handle) {
			::close(m_handle);
		}
	}
public:
	explicit operator PosixSocketHandle() const {
		return m_handle;
	}
	auto get() const -> PosixSocketHandle {
		return m_handle;
	}

	explicit operator bool() const {
		return m_handle != invalid_handle;
	}
	auto operator !() const -> bool {
		return m_handle == invalid_handle;
	}

	SocketHandle() = default;
	~SocketHandle() {
		close();
	}

	explicit SocketHandle(PosixSocketHandle handle) :
		m_handle{handle}
	{}
	auto operator=(PosixSocketHandle handle) -> SocketHandle& {
		close();
		m_handle = handle;
		return *this;
	}

	SocketHandle(SocketHandle const&) = delete;
	auto operator=(SocketHandle const&) -> SocketHandle& = delete;

	SocketHandle(SocketHandle&& handle) :
		m_handle{handle.m_handle} 
	{
		handle.m_handle = invalid_handle;
	} 
	auto operator=(SocketHandle&& handle) -> SocketHandle& {
		m_handle = handle.m_handle;
		handle.m_handle = invalid_handle;
		return *this;
	}
};

class RawSocket {
private:
	SocketHandle m_handle;

	static auto get_address_info(std::u8string const server, utils::Port const port) 
	{
		auto const port_string = std::to_string(port);
		auto const hints = addrinfo{
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
		};
		auto address_info = static_cast<addrinfo*>(nullptr);

		while (auto const result = ::getaddrinfo(
			reinterpret_cast<char const*>(server.data()),
			port_string.data(),
			&hints, &address_info
		)) {
			if (result == EAI_AGAIN) {
				continue;
			}
			else if (result == EAI_NONAME) {
				throw errors::ConnectionFailed{};
			}
			else {
				utils::unix::throw_error("Failed to get address info for socket creation", result);
			}
		}

		return std::unique_ptr<addrinfo, decltype([](auto p){freeaddrinfo(p);})>{address_info};
	}

	static auto create_handle(std::u8string_view const server, utils::Port const port) -> SocketHandle {
		auto const address_info = get_address_info(std::u8string{server}, port);
		
		auto socket_handle = SocketHandle{::socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol)};
		if (!socket_handle) {
			utils::unix::throw_error("Failed to create socket");
		}
		
		while (::connect(socket_handle.get(), address_info->ai_addr, static_cast<int>(address_info->ai_addrlen)) == -1)
		{
			if (auto const error_code = errno; error_code != EINPROGRESS) {
				utils::unix::throw_error("Failed to connect socket", error_code);
			}
			constexpr auto milliseconds_to_wait_between_attempts = 1;
			sleep(milliseconds_to_wait_between_attempts);
		}

		return socket_handle;
	}

	auto receive_response() const -> SocketResponse {
		constexpr auto packet_size = 512;
		
		auto buffer = std::vector<std::byte>(packet_size);
		auto buffer_offset = 0ull;
		
		while (true) {
			if (auto const result = recv(m_handle.get(), reinterpret_cast<char*>(buffer.data() + buffer_offset), static_cast<int>(packet_size), 0); 
				result > 0) 
			{
				buffer_offset += result;
				buffer.resize(buffer_offset + packet_size);
			} 
			else if (result < 0) {
				utils::unix::throw_error("Failed to receive data through socket");
			}
			else break;
		}

		return SocketResponse{.data=std::move(buffer)};
	}

public:
	auto send(std::span<std::byte const> const data) const -> SocketResponse {
		if (::send(
			m_handle.get(), 
			reinterpret_cast<char const*>(data.data()), 
			static_cast<int>(data.size()), 
			0
		) == -1) {
			utils::unix::throw_error("Failed to send data through socket");
		}
		if (shutdown(m_handle.get(), SHUT_WR) == -1) {
			utils::unix::throw_error("Failed to shut down socket connection after sending data");
		}
		return receive_response();
	}

	RawSocket(std::u8string_view const server, utils::Port const port) :
		m_handle{create_handle(server, port)}
	{}
};

class TlsSocket {
	using OpenSslContext = std::unique_ptr<SSL_CTX, decltype([](auto x){SSL_CTX_free(x);})>;
	OpenSslContext m_ssl_context{SSL_CTX_new(TLS_method())};

	using OpenSslSocketHandle = std::unique_ptr<BIO, decltype([](auto a){BIO_free_all(a);})>;
	OpenSslSocketHandle m_handle;

	auto create_handle(std::u8string_view const server, utils::Port const port) const -> OpenSslSocketHandle {
		SSL_CTX_set_verify(m_ssl_context.get(), SSL_VERIFY_PEER, nullptr);
		SSL_CTX_set_options(m_ssl_context.get(), SSL_OP_ALL);

		auto const server_utf8_string = std::string{utils::u8string_to_utf8_string(server)};
		auto const server_with_port = server_utf8_string + ':' + std::to_string(port);

		auto const handle = BIO_new_ssl_connect(m_ssl_context.get());
		BIO_set_conn_hostname(handle, server_with_port.data());

		auto const ssl = static_cast<SSL*>(nullptr);
		BIO_get_ssl(handle, &ssl);

		SSL_set_tlsext_host_name(ssl, server_utf8_string.data());
		
		return OpenSslSocketHandle{handle};
	}

public:
	auto send(std::span<std::byte const> const data) const -> SocketResponse {
		return {};
	}

	TlsSocket(std::u8string_view const server, utils::Port const port) :
		m_handle{create_handle(server, port)} 
	{}
};

class SshSocket {
	SocketHandle m_handle;

	static auto create_handle(std::u8string_view const server, utils::Port const port) -> SocketHandle {
		return {};
	}
	
public:
	auto send(std::span<std::byte const> const data) const -> SocketResponse {
		return {};
	}

	SshSocket(std::u8string_view const server, utils::Port const port) :
		m_handle{create_handle(server, port)} 
	{}
};

class Socket::Implementation {
private:
	using SocketVariant = std::variant<RawSocket, TlsSocket, SshSocket>;
	SocketVariant m_socket;

	static auto select_socket(std::u8string_view const server, utils::Port const port)
		-> SocketVariant
	{
		switch (port) {
		case utils::get_port(utils::Protocol::Https):
			return TlsSocket{server, port};
		case utils::get_port(utils::Protocol::Sftp):
			return SshSocket{server, port};
		default:
			return RawSocket{server, port};
		}
	}

public:
	auto send(std::span<std::byte const> const data) const -> SocketResponse {
		if (std::holds_alternative<RawSocket>(m_socket)) {
			return std::get<RawSocket>(m_socket).send(data);
		}
		else if (std::holds_alternative<TlsSocket>(m_socket)) {
			return std::get<TlsSocket>(m_socket).send(data);
		}
		return std::get<SshSocket>(m_socket).send(data);
	}
	
	Implementation(std::u8string_view const server, utils::Port const port) :
		m_socket{select_socket(server, port)}
	{}
};

#endif // IS_POSIX

auto Socket::send(std::span<std::byte const> const data) const -> SocketResponse {
	return m_implementation->send(data);
}

Socket::Socket(std::u8string_view const server, utils::Port const port) :
	m_implementation{std::make_unique<Implementation>(server, port)}
{}

Socket::Socket() = default;
Socket::~Socket() = default;

Socket::Socket(Socket&&) = default;
auto Socket::operator=(Socket&&) -> Socket& = default;

} // namespace internet_client
