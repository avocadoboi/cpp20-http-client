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
#include <system_error>

// debugging
#include <iostream>

using namespace std::chrono_literals;

//---------------------------------------------------------

#ifdef _WIN32
#	define SECURITY_WIN32

// Windows socket API
#	include <winsock2.h>
#	include <ws2tcpip.h>

// Windows secure channel API
#	include <schannel.h>
#	include <sspi.h>
#elif __has_include(<unistd.h>) // This header must exist on platforms that conform to the POSIX specifications
// The POSIX library is available on this platform.
#	define IS_POSIX

#	include <arpa/inet.h>
#	include <errno.h>
#	include <fcntl.h>
#	include <netdb.h>
#	include <netinet/tcp.h>
#	include <sys/socket.h>
#	include <unistd.h>

#	include <openssl/err.h>
#	include <openssl/ssl.h>

// Name clash
#	ifdef unix
#		undef unix
#	endif
#endif // __has_include(<unistd.h>)

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

template<IsTrivial _Type, IsFunctorInvocable<_Type> _Deleter, _Type invalid_handle = _Type{}>
class UniqueHandle {
	_Type m_handle{invalid_handle};

	auto close() -> void {
		if (m_handle != invalid_handle) {
			_Deleter{}(m_handle);
			m_handle = invalid_handle;
		}
	}
public:
	explicit operator _Type() const {
		return m_handle;
	}
	auto get() const -> _Type {
		return m_handle;
	}
	auto get() -> _Type& {
		return m_handle;
	}

	auto operator->() const -> _Type const* {
		return &m_handle;
	}
	auto operator->() -> _Type* {
		return &m_handle;
	}

	auto operator&() const -> _Type const* {
		return &m_handle;
	}
	auto operator&() -> _Type* {
		return &m_handle;
	}

	explicit operator bool() const {
		return m_handle != invalid_handle;
	}
	auto operator!() const -> bool {
		return m_handle == invalid_handle;
	}

	explicit UniqueHandle(_Type handle) :
		m_handle{handle}
	{}
	auto operator=(_Type handle) -> UniqueHandle& {
		close();
		m_handle = handle;
		return *this;
	}

	UniqueHandle() = default;
	~UniqueHandle() {
		close();
	}

	UniqueHandle(UniqueHandle&& handle) noexcept :
		m_handle{handle.m_handle}
	{
		handle.m_handle = invalid_handle;
	}
	auto operator=(UniqueHandle&& handle) noexcept -> UniqueHandle& {
		m_handle = handle.m_handle;
		handle.m_handle = invalid_handle;
		return *this;
	}

	UniqueHandle(UniqueHandle const&) = delete;
	auto operator=(UniqueHandle const&) -> UniqueHandle& = delete;
};

#ifdef _WIN32
namespace win {

[[nodiscard]]
auto get_error_message(DWORD const message_id) -> std::string {
    auto buffer = static_cast<char*>(nullptr);

    [[maybe_unused]]
    auto const buffer_cleanup = Cleanup{[&]{LocalFree(buffer);}};

    auto const size = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS | 
        FORMAT_MESSAGE_ALLOCATE_BUFFER,
        nullptr,
        message_id,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        1,
        nullptr
    );

    return std::string(buffer, size);
}

[[nodiscard]]
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

auto utf8_to_wide(std::u8string_view const input, std::span<wchar_t> const output)
	-> void
{
	auto const length = MultiByteToWideChar(
		CP_UTF8, 0,
		reinterpret_cast<char const*>(input.data()), static_cast<int>(input.size()),
		output.data(), static_cast<int>(output.size())
	);

	if (length > 0) {
		output[length] = 0;
	}
}

[[nodiscard]]
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

auto wide_to_utf8(std::wstring_view const input, std::span<char8_t> const output) 
	-> void 
{
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

using UniqueBio = std::unique_ptr<BIO, decltype([](BIO* x){BIO_free(x);})>;

[[nodiscard]]
auto get_openssl_error_string() -> std::string {
	auto const memory_file_handle = UniqueBio{BIO_new(BIO_s_mem())};
	ERR_print_errors(memory_file_handle.get());
	
	auto buffer = static_cast<char*>(nullptr);
	auto const length = BIO_get_mem_data(memory_file_handle.get(), &buffer);

	return std::string(static_cast<char const*>(buffer), length);
}

} // namespace unix

#endif // IS_POSIX

//---------------------------------------------------------

#ifdef _WIN32

[[noreturn]]
auto throw_connection_error(
	std::string reason, 
	int const error_code = static_cast<int>(GetLastError()),
	bool const is_tls_error = false
) -> void 
{
	reason += " with code ";
	reason += std::to_string(error_code);
	reason += ": ";
	reason += win::get_error_message(error_code);
	throw errors::ConnectionFailed{reason, is_tls_error};
}

#endif // _WIN32

#ifdef IS_POSIX

[[nodiscard]]
auto throw_connection_error(std::string reason, int const error_code = errno, bool const is_tls_error = false) 
	-> void 
{
	reason += " with code ";
	reason += std::to_string(error_code);
	reason += ": ";
	reason += std::generic_category().message(error_code);
	throw errors::ConnectionFailed{reason, is_tls_error};
}

#endif // IS_POSIX

} // namespace utils

#ifdef _WIN32

class WinSockLifetime {
private:
	bool m_is_moved = false;

public:
	WinSockLifetime() {
		auto api_info = WSADATA{};
		if (auto const result = WSAStartup(MAKEWORD(2, 2), &api_info)) {
			utils::throw_connection_error("Failed to initialize Winsock API 2.2", result);
		}
	}
	~WinSockLifetime() {
		if (!m_is_moved) {
			WSACleanup();
		}
	}

	WinSockLifetime(WinSockLifetime&& other) noexcept {
		other.m_is_moved = true;
	}
	auto operator=(WinSockLifetime&& other) noexcept -> WinSockLifetime& {
		other.m_is_moved = true;
		m_is_moved = false;
		return *this;
	}

	WinSockLifetime(WinSockLifetime const&) = delete;
	auto operator=(WinSockLifetime const&) -> WinSockLifetime& = delete;
};

using SocketHandle = utils::UniqueHandle<
	SOCKET,
	decltype([](auto const socket) {
		if (shutdown(socket, SD_BOTH) == SOCKET_ERROR) {
			utils::throw_connection_error("Failed to shut down socket connection after sending data", WSAGetLastError());
		}
		closesocket(socket);
	}),
	INVALID_SOCKET
>;

class RawSocket {
private:
	WinSockLifetime m_api_lifetime;

	using AddressInfo = std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>;
	AddressInfo m_address_info;

	[[nodiscard]]
	static auto get_address_info(std::u8string_view const server, Port const port) -> AddressInfo
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
			else throw errors::ConnectionFailed{
				std::string("Failed to get address info for socket creation: ") + gai_strerror(result)
			};
		}

		return AddressInfo{address_info};
	}

	SocketHandle m_handle;

	[[nodiscard]]
	auto create_handle() const -> SocketHandle {
		auto const handle_error = [](auto error_message) {
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::throw_connection_error(error_message, error_code);
			}
			constexpr auto time_to_wait_between_attempts = 1ms;
			std::this_thread::sleep_for(time_to_wait_between_attempts);
		};

		auto socket_handle = SocketHandle{};
		while ((socket_handle = socket(
				m_address_info->ai_family, 
				m_address_info->ai_socktype, 
				m_address_info->ai_protocol
			)).get() == INVALID_SOCKET) 
		{
			handle_error("Failed to create socket");
		}

		while (connect(
				socket_handle.get(), 
				m_address_info->ai_addr, 
				static_cast<int>(m_address_info->ai_addrlen)
			) == SOCKET_ERROR)
		{
			handle_error("Failed to connect socket");
		}

		return socket_handle;
	}

	bool m_is_nonblocking = false;

public:
	auto set_is_nonblocking(bool const p_is_nonblocking) -> void {
		if (m_is_nonblocking == p_is_nonblocking) {
			return;
		}
		auto is_nonblocking = static_cast<u_long>(p_is_nonblocking);
		ioctlsocket(m_handle.get(), FIONBIO, &is_nonblocking);
	}
	[[nodiscard]]
	auto get_winsock_handle() -> SOCKET {
		return m_handle.get();
	}

private:
	bool m_is_closed = false;
	
	auto reconnect() -> void {
		m_handle = create_handle();
		m_is_closed = false;
	}
public:
	auto write(std::span<std::byte const> const data) -> void {
		if (m_is_closed) {
			reconnect();
		}

		if (::send(
				m_handle.get(), 
				reinterpret_cast<char const*>(data.data()), 
				static_cast<int>(data.size()), 
				0
			) == SOCKET_ERROR) 
		{
			utils::throw_connection_error("Failed to send data through socket", WSAGetLastError());
		}
	}
	[[nodiscard]]
	auto read(std::span<std::byte> const buffer, bool const is_nonblocking = false) 
		-> std::variant<ConnectionClosed, std::size_t>
	{
		if (m_is_closed) {
			return std::size_t{};
		}

		set_is_nonblocking(is_nonblocking);

		if (auto const receive_result = recv(
				m_handle.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()), 
				0
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				m_is_closed = true;
				return ConnectionClosed{};
			} 
			return static_cast<std::size_t>(receive_result);
		}
		else if (is_nonblocking && WSAGetLastError() == WSAEWOULDBLOCK) {
			return std::size_t{};
		}
		else utils::throw_connection_error("Failed to receive data through socket");

		utils::unreachable();
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		return read(buffer, true);
	}

	RawSocket(std::u8string_view const server, Port const port) :
		m_address_info{get_address_info(server, port)},
		m_handle{create_handle()}
	{}
};

[[nodiscard]]
constexpr auto operator==(CredHandle const& first, CredHandle const& second) noexcept -> bool {
	return first.dwLower == second.dwLower && first.dwUpper == second.dwUpper;
}
[[nodiscard]]
constexpr auto operator!=(CredHandle const& first, CredHandle const& second) noexcept -> bool {
	return !(first == second);
}

[[nodiscard]]
constexpr auto operator==(SecBuffer const& first, SecBuffer const& second) noexcept -> bool {
	return first.pvBuffer == second.pvBuffer;
}
[[nodiscard]]
constexpr auto operator!=(SecBuffer const& first, SecBuffer const& second) noexcept -> bool {
	return !(first == second);
}

using SecurityContextHandle = utils::UniqueHandle<CtxtHandle, decltype([](auto& h){DeleteSecurityContext(&h);})>;
using SecurityContextBuffer = utils::UniqueHandle<
	SecBuffer, decltype([](auto& h){
		if (h.pvBuffer) {
			FreeContextBuffer(h.pvBuffer);
		}
	})
>;

struct SchannelConnectionInitializer {
	using CredentialsHandle = utils::UniqueHandle<CredHandle, decltype([](auto& h){FreeCredentialHandle(&h);})>;

	CredentialsHandle m_credentials = aquire_credentials_handle();

	[[nodiscard]]
	static auto aquire_credentials_handle() -> CredentialsHandle {
		auto credentials_data = SCHANNEL_CRED{
			.dwVersion = SCHANNEL_CRED_VERSION,
			.grbitEnabledProtocols = SP_PROT_TLS1_CLIENT,
		};
		CredHandle credentials_handle;
		TimeStamp credentials_time_limit;
		
		auto const security_status = AcquireCredentialsHandle(
			nullptr,
			UNISP_NAME,
			SECPKG_CRED_OUTBOUND,
			nullptr,
			&credentials_data,
			nullptr,
			nullptr,
			&credentials_handle,
			&credentials_time_limit
		); 
		if (security_status != SEC_E_OK) {
			utils::throw_connection_error("Failed to aquire credentials", security_status, true);
		}
		
		return CredentialsHandle{credentials_handle};
	}

	RawSocket* m_socket;
	std::wstring m_server_name;

	SecurityContextHandle m_security_context;
	
	auto query_stream_sizes() -> SecPkgContext_StreamSizes {
		SecPkgContext_StreamSizes stream_sizes;
		if (auto const result = QueryContextAttributesW(&m_security_context, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
			result != SEC_E_OK) 
		{
			utils::throw_connection_error("Failed to query Schannel security context stream sizes", result, true);
		}
		return stream_sizes;
	}
	
	// struct SingleBufferDescription {
	// 	SecBuffer security_buffer;
	// 	SecBufferDesc security_buffer_description;

	// 	SingleBufferDescription(std::span<std::byte> const buffer) :

	// 	{}
	// };

	using HandshakeOutputBuffer = utils::UniqueHandle<
		SecBuffer, decltype([](auto const& buffer){
			if (buffer.pvBuffer) {
				FreeContextBuffer(buffer.pvBuffer);
			}
		})
	>;

	struct [[nodiscard]] HandshakeProcessResult {
		SECURITY_STATUS status_code;
		HandshakeOutputBuffer output_buffer;
	};
	auto process_handshake_data(std::span<std::byte> const input_buffer) 
		-> HandshakeProcessResult
	{
		constexpr auto request_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
			ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

		auto input_security_buffer = SecBuffer{
			.cbBuffer = static_cast<std::uint32_t>(input_buffer.size()),
			.BufferType = SECBUFFER_TOKEN,
			.pvBuffer = input_buffer.data(),
		};
		auto input_security_buffer_description = SecBufferDesc{
			.ulVersion = SECBUFFER_VERSION,
			.cBuffers = 1ul,
			.pBuffers = &input_security_buffer,
		};

		auto output_security_buffer = HandshakeOutputBuffer{};
		auto output_security_buffer_description = SecBufferDesc{
			.ulVersion = SECBUFFER_VERSION,
			.cBuffers = 1ul,
			.pBuffers = &output_security_buffer,
		};
		
		unsigned long returned_flags;

		auto const return_code = InitializeSecurityContextW(
			&m_credentials.get(),
			m_security_context ? &m_security_context : nullptr, // Null on first call, input security context handle
			m_server_name.data(),
			request_flags,
			0, // Reserved
			0, // Not used with Schannel
			input_buffer.empty() ? nullptr : &input_security_buffer_description, // Null on first call
			0, // Reserved
			&m_security_context, // Output security context handle
			&output_security_buffer_description,
			&returned_flags,
			nullptr // Don't care about expiration date right now
		);

		return HandshakeProcessResult{[&]{
			if (return_code == SEC_I_COMPLETE_AND_CONTINUE || return_code == SEC_I_COMPLETE_NEEDED) {
				CompleteAuthToken(&m_security_context, &output_security_buffer_description);

				if (return_code == SEC_I_COMPLETE_AND_CONTINUE) {
					return SEC_I_CONTINUE_NEEDED;
				}
				return SEC_E_OK;
			}
			return return_code;
		}(), std::move(output_security_buffer)};
	}
	auto send_handshake_message(HandshakeOutputBuffer const& message_buffer) -> void {
		m_socket->write(std::span{static_cast<std::byte*>(message_buffer->pvBuffer), message_buffer->cbBuffer});
	}
	auto read_response(std::span<std::byte> const buffer, std::size_t const read_offset) -> std::span<std::byte> {
		if (auto const read_result = m_socket->read(buffer.subspan(read_offset));
			std::holds_alternative<ConnectionClosed>(read_result)) 
		{
			throw errors::ConnectionFailed{"The connection closed unexpectedly while reading handshake data.", true};
		}
		else return buffer.subspan(0, read_offset + std::get<std::size_t>(read_result));
	} 
	auto do_handshake() -> void {
		/*
			When the buffer for received handshake messages is too small, the return code from InitializeSecurityContextW 
			is not SEC_E_INCOMPLETE_MESSAGE, but SEC_E_INVALID_TOKEN. Trying to grow the buffer after
			getting that return code does not work. The server closes the connection when trying to read
			more data afterwards. It seems that we need a fixed maximum handshake message/token size.

			It is not clear exactly what this maximum size should be.
			The only thing Microsoft's documentation says about this is 
				"[...] the value of this parameter is a pointer to a 
				 buffer allocated with enough memory to hold the 
				 token returned by the remote computer."
				(https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)
			The TLS 1.3 standard specification says:
				"The record layer fragments information blocks into TLSPlaintext
   				 records carrying data in chunks of 2^14 bytes or less."
				(https://tools.ietf.org/html/rfc8446)
			
			Looking at a few implementations of TLS sockets using Schannel:
			1. https://github.com/adobe/chromium/blob/master/net/socket/ssl_client_socket_win.cc
				Uses 5 + 16*1024 + 64 = 16453 bytes.
			2. https://github.com/curl/curl/blob/master/lib/vtls/schannel.c
				Uses 4096 + 1024 = 5120 bytes.
			3. https://github.com/odzhan/shells/tree/master/s6
				Uses 32768 bytes.
			4. https://docs.microsoft.com/en-us/windows/win32/secauthn/using-sspi-with-a-windows-sockets-client
				Uses 12000 bytes.

			ALL of these implementations use DIFFERENT maximum handshake message sizes.
			I decided to follow the TLS specification and use 2^14 bytes for the handshake message buffer,
			as this should be the maximum allowed size of any TLSPlaintext record block, which includes handshake messages.
		*/
		constexpr auto maximum_message_size = std::size_t{1 << 14};

		if (auto const [return_code, output_buffer] = process_handshake_data({});
			return_code != SEC_I_CONTINUE_NEEDED) // First call should always yield this return code.
		{
			utils::throw_connection_error("Schannel TLS handshake initialization failed", return_code, true);
		}
		else send_handshake_message(output_buffer);
		
		auto input_buffer = utils::DataVector(maximum_message_size);

		auto read_start = std::size_t{};
		while (true) {
			if (auto const [return_code, output_buffer] = process_handshake_data(read_response(input_buffer, read_start));
				return_code == SEC_I_CONTINUE_NEEDED)
			{
				send_handshake_message(output_buffer);
				read_start = std::size_t{};
			}
			else if (return_code == SEC_E_OK) {
				return;
			}
			else {
				utils::throw_connection_error("Schannel TLS handshake failed", return_code);
			}
		}
	}

public:
	auto operator()() && -> SecurityContextHandle {
		do_handshake();
		return std::move(m_security_context);
	}

	[[nodiscard]]
	SchannelConnectionInitializer(RawSocket* socket, std::u8string_view const server) :
		m_socket{socket},
		m_server_name{utils::win::utf8_to_wide(server)}
	{}
	~SchannelConnectionInitializer() = default;
	SchannelConnectionInitializer(SchannelConnectionInitializer&&) noexcept = delete;
	auto operator=(SchannelConnectionInitializer&&) noexcept -> SchannelConnectionInitializer& = delete;
	SchannelConnectionInitializer(SchannelConnectionInitializer const&) = delete;
	auto operator=(SchannelConnectionInitializer const&) -> SchannelConnectionInitializer& = delete;
};

class TlsSocket {
private:
	std::unique_ptr<RawSocket> m_raw_socket;
	SecurityContextHandle m_security_context;

	auto initialize_connection(std::u8string_view const server, Port const port) -> void {
		if (m_raw_socket) {
			return;
		}

		m_raw_socket = std::make_unique<RawSocket>(server, port);

		m_security_context = SchannelConnectionInitializer{m_raw_socket.get(), server}();
	}

public:
	auto write(std::span<std::byte const> const /*data*/) -> void {
	}

	[[nodiscard]]
	auto read(std::span<std::byte> const /*buffer*/, bool const /* is_nonblocking */ = false) 
		-> std::variant<ConnectionClosed, std::size_t>
	{
		return {};
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const /* buffer */) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		return {};
	}

	TlsSocket(std::u8string_view const server, Port const port) {
		initialize_connection(server, port);
	}
};

#endif // _WIN32

#ifdef IS_POSIX

using PosixSocketHandle = int;

using SocketHandle = utils::UniqueHandle<
	PosixSocketHandle, 
	decltype([](auto const handle){
		if (::shutdown(handle, SHUT_RDWR) == -1) {
			utils::throw_connection_error("Failed to shut down socket connection");
		}
		::close(handle);		
	}),
	PosixSocketHandle{-1}
>;

class RawSocket {
private:
	using AddressInfo = std::unique_ptr<addrinfo, decltype([](auto const p){freeaddrinfo(p);})>;
	AddressInfo m_address_info;

	[[nodiscard]]
	static auto get_address_info(std::u8string const server, Port const port) -> AddressInfo
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
			else throw errors::ConnectionFailed{
				std::string("Failed to get address info for socket creation: ") + gai_strerror(result)
			};
		}

		return AddressInfo{address_info};
	}

	SocketHandle m_handle;

	[[nodiscard]]
	auto create_handle() const -> SocketHandle {
		auto socket_handle = SocketHandle{::socket(
			m_address_info->ai_family, 
			m_address_info->ai_socktype, 
			m_address_info->ai_protocol
		)};
		if (!socket_handle) {
			utils::throw_connection_error("Failed to create socket");
		}

		while (::connect(
				socket_handle.get(), 
				m_address_info->ai_addr, 
				static_cast<int>(m_address_info->ai_addrlen)
			) == -1)
		{
			if (auto const error_code = errno; error_code != EINPROGRESS) {
				utils::throw_connection_error("Failed to connect socket", error_code);
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
				utils::throw_connection_error("Failed to turn on nonblocking mode on socket");
			}
			m_is_nonblocking = true;
		}
	}
	auto make_blocking() -> void {
		if (m_is_nonblocking) {
			auto const flags = fcntl(m_handle.get(), F_GETFL);
			if (-1 == fcntl(m_handle.get(), F_SETFL, flags & ~O_NONBLOCK)) {
				utils::throw_connection_error("Failed to turn off nonblocking mode on socket");
			}
			m_is_nonblocking = false;
		}
	}
	[[nodiscard]]
	auto get_posix_handle() -> PosixSocketHandle {
		return m_handle.get();
	}
	
private:
	bool m_is_closed = false;

public:
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
			utils::throw_connection_error("Failed to send data through socket");
		}
	}
	[[nodiscard]]
	auto read(std::span<std::byte> const buffer, bool is_nonblocking = false) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		if (m_is_closed) {
			return std::size_t{};
		}

		if (auto const receive_result = recv(
				m_handle.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()),
				is_nonblocking ? MSG_DONTWAIT : 0
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				m_is_closed = true;
				return ConnectionClosed{};
			}
			return static_cast<std::size_t>(receive_result);
		}
		else if (is_nonblocking && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			return std::size_t{};
		}
		utils::throw_connection_error("Failed to receive data through socket");
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) -> std::variant<ConnectionClosed, std::size_t> {
		return read(buffer, true);
	}

	RawSocket(std::u8string_view const server, Port const port) :
		m_address_info{get_address_info(std::u8string{server}, port)}, 
		m_handle{create_handle()}
	{}
};

class TlsSocket {
	static auto throw_tls_error() -> void {
		throw errors::ConnectionFailed{utils::unix::get_openssl_error_string(), true};
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

	auto update_tls_socket_handle() -> void {
		if (1 != SSL_set_fd(m_tls_connection.get(), m_raw_socket->get_posix_handle())) {
			throw_tls_error();
		}
	}
	
	auto configure_tls_context() -> void {
		// SSL_CTX_set_options(m_tls_context.get(), SSL_OP_ALL);

		if (1 != SSL_CTX_set_default_verify_paths(m_tls_context.get())) {
			throw_tls_error();
		}
		SSL_CTX_set_read_ahead(m_tls_context.get(), true);
	}

	auto configure_tls_connection(std::u8string const server, Port const port) -> void {
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
		else throw_tls_error();

		// Get result of the certificate verification
		auto const verify_result = SSL_get_verify_result(m_tls_connection.get());
		if (X509_V_OK != verify_result) {
			throw_tls_error();
		}
	}

	auto initialize_connection(std::u8string_view const server, Port const port) -> void {
		if (m_raw_socket) {
			return;
		}

		configure_tls_context();
		configure_tls_connection(std::u8string{server}, port);
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
			utils::throw_connection_error("Failed to send data through socket");
		}
	}
	[[nodiscard]]
	auto read(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
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
		utils::throw_connection_error("Failed to receive data from socket");
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
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
		else switch (auto const error_code = SSL_get_error(m_tls_connection.get(), read_result)) {
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
				utils::throw_connection_error("Failed to read available data from socket");
		}
		utils::unreachable();
	}

	TlsSocket(std::u8string_view const server, Port const port) {
		initialize_connection(server, port);
	}
};
#endif // IS_POSIX

class Socket::Implementation {
private:
	using SocketVariant = std::variant<RawSocket, TlsSocket>;
	SocketVariant m_socket;

	[[nodiscard]]
	static auto select_socket(std::u8string_view const server, Port const port)
		-> SocketVariant
	{
		if (port == utils::get_port(Protocol::Http)) {
			return RawSocket{server, port};
		}
		return TlsSocket{server, port};
	}

public:
	auto write(std::span<std::byte const> const buffer) -> void {
		if (std::holds_alternative<RawSocket>(m_socket)) {
			std::get<RawSocket>(m_socket).write(buffer);
		}
		else std::get<TlsSocket>(m_socket).write(buffer);
	}
	[[nodiscard]]
	auto read(std::span<std::byte> const buffer)
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		if (std::holds_alternative<RawSocket>(m_socket)) {
			return std::get<RawSocket>(m_socket).read(buffer);
		}
		return std::get<TlsSocket>(m_socket).read(buffer);
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		if (std::holds_alternative<RawSocket>(m_socket)) {
			return std::get<RawSocket>(m_socket).read_available(buffer);
		}
		return std::get<TlsSocket>(m_socket).read_available(buffer);
	}

	Implementation(std::u8string_view const server, Port const port) :
		m_socket{select_socket(server, port)}
	{}
};

auto Socket::write(std::span<std::byte const> data) const -> void {
	m_implementation->write(data);
}

auto Socket::read(std::span<std::byte> buffer) const 
	-> std::variant<ConnectionClosed, std::size_t> 
{
	return m_implementation->read(buffer);
}

auto Socket::read_available(std::span<std::byte> buffer) const 
	-> std::variant<ConnectionClosed, std::size_t> 
{
	return m_implementation->read_available(buffer);
}

Socket::Socket(std::u8string_view const server, Port const port) :
	m_implementation{std::make_unique<Implementation>(server, port)}
{}
Socket::~Socket() = default;

Socket::Socket(Socket&&) noexcept = default;
auto Socket::operator=(Socket&&) noexcept -> Socket& = default;

} // namespace internet_client
