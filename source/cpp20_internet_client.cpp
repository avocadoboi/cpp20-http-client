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

#include <array>
#include <chrono>
#include <span>
#include <system_error>
#include <variant>

// debugging
#include <iostream>

using namespace std::chrono_literals;

//---------------------------------------------------------

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#elif __has_include(<unistd.h>) // This header must exist on platforms that conform to the POSIX specifications

// The POSIX library is available on this platform.
#define IS_POSIX

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

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

} // namespace win

#endif // _WIN32

#ifdef IS_POSIX

namespace unix {

auto print_openssl_errors() -> void {
	ERR_print_errors_fp(stdout);
}

} // namespace unix

#endif // IS_POSIX

//---------------------------------------------------------

#ifdef _WIN32

auto throw_system_error(
	std::string reason,
	std::error_code const error_code = static_cast<int>(GetLastError())
) -> void {
	reason += " with code ";
	reason += std::to_string(error_code.value());
	throw std::system_error{error_code, std::system_category(), reason};
}

#endif // _WIN32

#ifdef IS_POSIX

auto throw_system_error(
	std::string reason,
	int const error_code = errno
) -> void {
	reason += " with code ";
	reason += std::to_string(error_code);
	throw std::system_error{error_code, std::generic_category(), reason};
}

#endif // IS_POSIX

} // namespace utils

#ifdef _WIN32

class WinSockLifetime {
public:
	WinSockLifetime() {
		auto api_info = WSADATA{};
		if (auto const result = WSAStartup(MAKEWORD(2, 2), &api_info)) {
			utils::throw_system_error("Failed to initialize Winsock API 2.2", result);
		}
	}
	~WinSockLifetime() {
		WSACleanup();
	}

	WinSockLifetime(WinSockLifetime&&) = delete;
	auto operator=(WinSockLifetime&&) -> WinSockLifetime& = delete;

	WinSockLifetime(WinSockLifetime const&) = delete;
	auto operator=(WinSockLifetime const&) -> WinSockLifetime& = delete;
};

class SocketHandle {
private:
	SOCKET m_handle{INVALID_SOCKET};

	auto close() const -> void {
		if (m_handle != INVALID_SOCKET) {
			if (shutdown(m_handle, SD_BOTH) == SOCKET_ERROR) {
				utils::throw_system_error("Failed to shut down socket connection after sending data", WSAGetLastError());
			}
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
	~SocketHandle() {
		close();
	}

	explicit SocketHandle(SOCKET handle) :
		m_handle{handle}
	{}
	auto operator=(SOCKET handle) -> SocketHandle& {
		close();
		m_handle = handle;
		return *this;
	}

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

	SocketHandle(SocketHandle const&) = delete;
	auto operator=(SocketHandle const&) -> SocketHandle& = delete;
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
				&hints, 
				&address_info
			)) 
		{
			if (result == EAI_AGAIN) {
				continue;
			}
			else if (result == WSAHOST_NOT_FOUND) {
				throw errors::ConnectionFailed{};
			}
			else {
				utils::throw_system_error("Failed to get address info for socket creation", result);
			}
		}

		return std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>{address_info};
	}

	static auto create_handle(std::u8string_view const server, utils::Port const port) -> SocketHandle {
		auto const address_info = get_address_info(server, port);

		auto const handle_error = [](auto error_message) {
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::throw_system_error(error_message, error_code);
			}
			constexpr auto time_to_wait_between_attempts = 1ms;
			std::this_thread::sleep_for(time_to_wait_between_attempts);
		};

		auto socket_handle = SocketHandle{};
		while ((socket_handle = socket(
				address_info->ai_family, 
				address_info->ai_socktype, 
				address_info->ai_protocol
			)).get() == INVALID_SOCKET) 
		{
			handle_error("Failed to create socket");
		}

		while (connect(
				socket_handle.get(), 
				address_info->ai_addr, 
				static_cast<int>(address_info->ai_addrlen)
			) == SOCKET_ERROR)
		{
			handle_error("Failed to connect socket");
		}

		return socket_handle;
	}

public:
	auto write(std::span<std::byte const> const data) -> void {
		if (::send(
				m_handle.get(), 
				reinterpret_cast<char const*>(data.data()), 
				static_cast<int>(data.size()), 
				0
			) == SOCKET_ERROR) 
		{
			utils::throw_system_error("Failed to send data through socket", WSAGetLastError());
		}
		if (shutdown(m_handle.get(), SD_SEND) == SOCKET_ERROR) {
			utils::throw_system_error("Failed to shut down socket connection after sending data", WSAGetLastError());
		}
	}
	auto read(std::span<std::byte> buffer) -> std::size_t {
		if (auto const result = recv(
				m_handle.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()), 
				0
			); result >= 0)
		{
			return static_cast<std::size_t>(result);
		}
		else {
			utils::throw_system_error("Failed to receive data through socket");
		}
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
	constexpr static auto invalid_handle = PosixSocketHandle{-1};

	PosixSocketHandle m_handle{invalid_handle};

	auto close() const -> void {
		if (m_handle != invalid_handle) {
			if (::shutdown(m_handle, SHUT_RDWR) == -1) {
				utils::throw_system_error("Failed to shut down socket connection");
			}
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

	explicit SocketHandle(PosixSocketHandle handle) :
		m_handle{handle}
	{}
	auto operator=(PosixSocketHandle handle) -> SocketHandle& {
		close();
		m_handle = handle;
		return *this;
	}

	SocketHandle() = default;
	~SocketHandle() {
		close();
	}

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

	SocketHandle(SocketHandle const&) = delete;
	auto operator=(SocketHandle const&) -> SocketHandle& = delete;
};

class RawSocket {
private:
	using AddressInfo = std::unique_ptr<addrinfo, decltype([](auto p){freeaddrinfo(p);})>;
	AddressInfo m_address_info;

	static auto get_address_info(std::u8string const server, utils::Port const port) -> AddressInfo
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
				&hints, 
				&address_info
			))
		{
			if (result == EAI_AGAIN) {
				continue;
			}
			else if (result == EAI_NONAME) {
				throw errors::ConnectionFailed{};
			}
			else {
				utils::throw_system_error("Failed to get address info for socket creation", result);
			}
		}

		return AddressInfo{address_info};
	}

	SocketHandle m_handle;

	auto create_handle() const -> SocketHandle {
		auto socket_handle = SocketHandle{::socket(
			m_address_info->ai_family, 
			m_address_info->ai_socktype, 
			m_address_info->ai_protocol
		)};
		if (!socket_handle) {
			utils::throw_system_error("Failed to create socket");
		}

		while (::connect(
				socket_handle.get(), 
				m_address_info->ai_addr, 
				static_cast<int>(m_address_info->ai_addrlen)
			) == -1)
		{
			if (auto const error_code = errno; error_code != EINPROGRESS) {
				utils::throw_system_error("Failed to connect socket", error_code);
			}
			constexpr auto time_to_wait_between_attempts = 1ms;
			std::this_thread::sleep_for(time_to_wait_between_attempts);
		}

		// auto const enable_value = 1;
		// setsockopt(socket_handle.get(), IPPROTO_TCP, TCP_QUICKACK, &enable_value, sizeof(enable_value));

		return socket_handle;
	}

	bool m_is_nonblocking = false;

public:
	auto make_nonblocking() -> void {
		if (!m_is_nonblocking) {
			auto const flags = fcntl(m_handle.get(), F_GETFL);
			if (-1 == fcntl(m_handle.get(), F_SETFL, flags | O_NONBLOCK)) {
				utils::throw_system_error("Failed to turn on nonblocking mode on socket");
			}
			m_is_nonblocking = true;
		}
	}
	auto make_blocking() -> void {
		if (m_is_nonblocking) {
			auto const flags = fcntl(m_handle.get(), F_GETFL);
			if (-1 == fcntl(m_handle.get(), F_SETFL, flags & ~O_NONBLOCK)) {
				utils::throw_system_error("Failed to turn off nonblocking mode on socket");
			}
			m_is_nonblocking = false;
		}
	}
	auto get_posix_handle() -> PosixSocketHandle {
		return m_handle.get();
	}
	
private:
	bool m_is_closed = false;

public:
	// auto get_is_closed() -> bool {
	// 	return m_is_closed;
	// }
	auto reconnect() -> void {
		m_handle = create_handle();
		m_is_closed = false;
	}

	auto write(std::span<std::byte const> const data) -> void {
		if (m_is_closed) {
			reconnect();
		}

		if (::send(
				m_handle.get(),
				data.data(),
				static_cast<int>(data.size()),
				0
			) == -1) 
		{
			utils::throw_system_error("Failed to send data through socket");
		}
	}
	auto read(std::span<std::byte> const buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (m_is_closed) {
			return std::size_t{};
		}

		if (auto const receive_result = ::read(
				m_handle.get(), 
				buffer.data(), 
				static_cast<int>(buffer.size())
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				m_is_closed = true;
				return ConnectionClosed{};
			}
			return static_cast<std::size_t>(receive_result);
		}
		else {
			utils::throw_system_error("Failed to receive data through socket");
		}
		return {};
	}
	auto read_available(std::span<std::byte> const buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (m_is_closed) {
			return std::size_t{};
		}
		
		if (auto const receive_result = recv(
				m_handle.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()), 
				MSG_DONTWAIT
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				m_is_closed = true;
				return ConnectionClosed{};
			}
			return static_cast<std::size_t>(receive_result);
		}
		else if (errno == EWOULDBLOCK || errno == EAGAIN) {
			return std::size_t{};
		}
		else {
			utils::throw_system_error("Failed to receive data through socket");
		}
		return {};
	}

	// auto close() -> void {
	// 	if (shutdown(m_handle.get(), SHUT_WR) == -1) {
	// 		utils::throw_system_error("Failed to shut down socket connection");
	// 	}
	// 	m_is_closed = true;
	// }

	RawSocket(std::u8string_view const server, utils::Port const port) :
		m_address_info{get_address_info(std::u8string{server}, port)}, 
		m_handle{create_handle()}
	{}
};

class TlsSocket {
	static auto throw_tls_error() -> void {
		utils::unix::print_openssl_errors();
		throw errors::ConnectionFailed{.was_tls_failure = true};
	}

	using TlsContext = std::unique_ptr<SSL_CTX, decltype([](auto x){SSL_CTX_free(x);})>;
	TlsContext m_tls_context = []{
		if (auto const method = TLS_client_method()) {
			if (auto const tls = SSL_CTX_new(method)) {
				return TlsContext{tls};
			}
		}
		throw_tls_error();
		return TlsContext{};
	}();

	using TlsConnection = std::unique_ptr<SSL, decltype([](auto x){SSL_free(x);})>;
	TlsConnection m_tls_connection = [this]{
		if (auto const tls_connection = SSL_new(m_tls_context.get())) {
			return TlsConnection{tls_connection};
		}
		throw_tls_error();
		return TlsConnection{};
	}();

	std::unique_ptr<RawSocket> m_raw_socket;

	auto configure_tls_context() -> void {
		// SSL_CTX_set_options(m_tls_context.get(), SSL_OP_ALL);

		if (1 != SSL_CTX_set_default_verify_paths(m_tls_context.get())) {
			throw_tls_error();
		}
		SSL_CTX_set_read_ahead(m_tls_context.get(), true);
	}

	auto update_tls_socket_handle() -> void {
		if (1 != SSL_set_fd(m_tls_connection.get(), m_raw_socket->get_posix_handle())) {
			throw_tls_error();
		}
	}
	auto configure_tls_connection(std::u8string const server, utils::Port const port) -> void {
		auto const host_name_c_string = utils::u8string_to_utf8_string(server).data();

		// For SNI (Server Name Identification)
		if (1 != SSL_set_tlsext_host_name(m_tls_connection.get(), host_name_c_string)) {
			throw_tls_error();
		}
		// Configure automatic hostname check
		if (1 != SSL_set1_host(m_tls_connection.get(), host_name_c_string)) {
			throw_tls_error();
		}

		// Set the socket to be used by the tls connection
		m_raw_socket = std::make_unique<RawSocket>(server, port);
		update_tls_socket_handle();
	}

	auto connect() -> void {
		SSL_connect(m_tls_connection.get());

		// Just to check that a certificate was presented by the server
		if (auto const certificate = SSL_get_peer_certificate(m_tls_connection.get())) {
			X509_free(certificate);
		}
		else {
			throw_tls_error();
		}

		// Get result of the certificate verification
		auto const verify_result = SSL_get_verify_result(m_tls_connection.get());
		if (X509_V_OK != verify_result) {
			throw_tls_error();
		}
	}

	auto initialize_connection(std::u8string const server, utils::Port const port) -> void {
		if (m_raw_socket) {
			return;
		}

		configure_tls_context();
		configure_tls_connection(server, port);
		connect();
	}

	bool m_is_closed = false;

	auto ensure_connected() -> void {
		if (m_is_closed) {
			m_raw_socket->reconnect();
			update_tls_socket_handle();
			// connect();
		}
	}

public:
	// auto get_is_closed() -> bool {
	// 	return m_is_closed;
	// }

	auto write(std::span<std::byte const> const data) -> void {
		ensure_connected();
		
		if (SSL_write(
				m_tls_connection.get(),
				data.data(),
				static_cast<int>(data.size())
			) == -1)
		{
			utils::throw_system_error("Failed to send data through socket");
		}
	}
	auto read(std::span<std::byte> buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (m_is_closed) {
			return std::size_t{};
		}
		
		m_raw_socket->make_blocking();
		if (auto const read_result = SSL_read(
				m_tls_connection.get(),
				buffer.data(),
				static_cast<int>(buffer.size())
			); read_result >= 0) 
		{
			if (read_result == 0) {
				m_is_closed = true;
				return ConnectionClosed{};
			}
			return static_cast<std::size_t>(read_result);
		}
		else {
			utils::throw_system_error("Failed to receive data from socket");
		}
		return {};
	}
	auto read_available(std::span<std::byte> buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (m_is_closed) {
			return std::size_t{};
		}
		
		m_raw_socket->make_nonblocking();
		if (auto const read_result = SSL_read(
				m_tls_connection.get(),
				buffer.data(),
				static_cast<int>(buffer.size())
			); read_result > 0)
		{
			return static_cast<std::size_t>(read_result);
		}
		else{ 
			switch (auto const error_code = SSL_get_error(m_tls_connection.get(), read_result))
			{
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					// No available data to read at the moment.
					return std::size_t{};
				case SSL_ERROR_ZERO_RETURN:
				case SSL_ERROR_SYSCALL:
					if (errno == 0) {
						m_is_closed = true;
						// Peer shut down the connection.
						return ConnectionClosed{};
					}
				default:
					utils::throw_system_error("Failed to read available data from socket");
			}
		}
		return {};
	}

	// auto shut_down() -> void {
	// 	if (SSL_shutdown(m_tls_connection.get()) < 0) {
	// 		utils::throw_system_error("Failed to shut down socket connection after sending data");
	// 	}
	// }

	TlsSocket(std::u8string_view const server, utils::Port const port) {
		initialize_connection(std::u8string{server}, port);
	}
};

class Socket::Implementation {
private:
	using SocketVariant = std::variant<RawSocket, TlsSocket>;
	SocketVariant m_socket;

	[[nodiscard]]
	static auto select_socket(std::u8string_view const server, utils::Port const port)
		-> SocketVariant
	{
		if (port == utils::get_port(utils::Protocol::Http)) {
			return RawSocket{server, port};
		}
		return TlsSocket{server, port};
	}

public:
	auto write(std::span<std::byte const> const buffer) -> void {
		if (std::holds_alternative<RawSocket>(m_socket)) {
			std::get<RawSocket>(m_socket).write(buffer);
		}
		else {
			std::get<TlsSocket>(m_socket).write(buffer);
		}
	}
	auto read(std::span<std::byte> const buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (std::holds_alternative<RawSocket>(m_socket)) {
			return std::get<RawSocket>(m_socket).read(buffer);
		}
		return std::get<TlsSocket>(m_socket).read(buffer);
	}
	auto read_available(std::span<std::byte> const buffer) -> std::variant<ConnectionClosed, std::size_t> {
		if (std::holds_alternative<RawSocket>(m_socket)) {
			return std::get<RawSocket>(m_socket).read_available(buffer);
		}
		return std::get<TlsSocket>(m_socket).read_available(buffer);
	}

	// auto get_is_closed() -> bool {
	// 	if (std::holds_alternative<RawSocket>(m_socket)) {
	// 		return std::get<RawSocket>(m_socket).get_is_closed();
	// 	}
	// 	return std::get<TlsSocket>(m_socket).get_is_closed();
	// }
	// auto shut_down() -> void {
	// 	if (std::holds_alternative<RawSocket>(m_socket)) {
	// 		std::get<RawSocket>(m_socket).shut_down();
	// 	}
	// 	else {
	// 		std::get<TlsSocket>(m_socket).shut_down();
	// 	}
	// }

	Implementation(std::u8string_view const server, utils::Port const port) :
		m_socket{select_socket(server, port)}
	{}
};

#endif // IS_POSIX

auto Socket::write(std::span<std::byte const> data) const -> void {
	m_implementation->write(data);
}

auto Socket::read(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t> {
	return m_implementation->read(buffer);
}

auto Socket::read_available(std::span<std::byte> buffer) const -> std::variant<ConnectionClosed, std::size_t> {
	return m_implementation->read_available(buffer);
}

// auto Socket::get_is_closed() const -> bool {
// 	return m_implementation->get_is_closed();
// }

// auto Socket::shut_down() const -> void {
// 	m_implementation->shut_down();
// }

Socket::Socket(std::u8string_view const server, utils::Port const port) :
	m_implementation{std::make_unique<Implementation>(server, port)}
{}
Socket::~Socket() = default;

Socket::Socket(Socket&&) = default;
auto Socket::operator=(Socket&&) -> Socket& = default;

} // namespace internet_client
