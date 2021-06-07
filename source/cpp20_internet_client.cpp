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

#include "cpp20_internet_client.hpp"

//---------------------------------------------------------

#include <cassert>
#include <chrono>
#include <cstring>
#include <system_error>

using namespace std::chrono_literals;

//---------------------------------------------------------

#ifdef _WIN32
// Required by SSPI API headers for some reason.
#	define SECURITY_WIN32

// Windows socket API.
#	include <winsock2.h>
#	include <ws2tcpip.h>

// Windows secure channel API.
#	include <schannel.h>
#	include <security.h>

// Mingw does not define this.
#	ifndef SECBUFFER_ALERT
		constexpr auto SECBUFFER_ALERT = 17;
#	endif
#elif __has_include(<unistd.h>) // This header must exist on platforms that conform to the POSIX specifications.
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

// Platform-specific utilities.
namespace utils {

void enable_utf8_console() {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif
	// Pretty much everyone else uses utf-8 by default.
}

#ifdef _WIN32
namespace win {

[[nodiscard]]
std::wstring utf8_to_wide(std::string_view const input) {
	auto result = std::wstring(MultiByteToWideChar(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		0, 0
	), '\0');

	MultiByteToWideChar(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		result.data(), static_cast<int>(result.size())
	);

	return result;
}

void utf8_to_wide(std::string_view const input, std::span<wchar_t> const output) {
	auto const length = MultiByteToWideChar(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		output.data(), static_cast<int>(output.size())
	);

	if (length > 0) {
		output[length] = 0;
	}
}

[[nodiscard]]
std::string wide_to_utf8(std::wstring_view const input) {
	auto result = std::string(WideCharToMultiByte(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		0, 0, nullptr, nullptr
	), '\0');

	WideCharToMultiByte(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		result.data(), static_cast<int>(result.size()),
		nullptr, nullptr
	);

	return result;
}

void wide_to_utf8(std::wstring_view const input, std::span<char> const output) {
	auto const length = WideCharToMultiByte(
		CP_UTF8, 0,
		input.data(), static_cast<int>(input.size()),
		output.data(), static_cast<int>(output.size()),
		nullptr, nullptr
	);

	if (length > 0) {
		output[length] = 0;
	}
}

[[nodiscard]]
std::string get_error_message(DWORD const message_id) {
    auto buffer = static_cast<wchar_t*>(nullptr);

    [[maybe_unused]]
    auto const buffer_cleanup = Cleanup{[&]{LocalFree(buffer);}};

    auto const size = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS | 
        FORMAT_MESSAGE_ALLOCATE_BUFFER,
        nullptr,
        message_id,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        1,
        nullptr
    );

    return wide_to_utf8(std::wstring_view{buffer, size});
}

} // namespace win

#endif // _WIN32

#ifdef IS_POSIX

namespace unix {

using UniqueBio = std::unique_ptr<BIO, decltype([](BIO* x){ BIO_free(x); })>;

[[nodiscard]]
std::string get_openssl_error_string() {
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
void throw_connection_error(
	std::string reason, 
	int const error_code = static_cast<int>(GetLastError()),
	bool const is_tls_error = false
) {
	reason += " with code ";
	reason += std::to_string(error_code);
	reason += ": ";
	reason += win::get_error_message(error_code);
	throw errors::ConnectionFailed{reason, is_tls_error};
}

#endif // _WIN32

#ifdef IS_POSIX

[[noreturn]]
void throw_connection_error(std::string reason, int const error_code = errno, bool const is_tls_error = false) {
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
public:
	WinSockLifetime() {
		auto api_info = WSADATA{};
		if (auto const result = WSAStartup(MAKEWORD(2, 2), &api_info)) {
			utils::throw_connection_error("Failed to initialize Winsock API 2.2", result);
		}
	}
	~WinSockLifetime() {
		if (!is_moved_) {
			WSACleanup();
		}
	}

	WinSockLifetime(WinSockLifetime&& other) noexcept {
		other.is_moved_ = true;
	}
	WinSockLifetime& operator=(WinSockLifetime&& other) noexcept {
		other.is_moved_ = true;
		is_moved_ = false;
		return *this;
	}

	WinSockLifetime(WinSockLifetime const&) = delete;
	WinSockLifetime& operator=(WinSockLifetime const&) = delete;

private:
	bool is_moved_{false};
};

using SocketHandle = utils::UniqueHandle<
	SOCKET,
	decltype([](auto const socket) {
		if (shutdown(socket, SD_BOTH) == SOCKET_ERROR) {
			utils::throw_connection_error("Failed to shut down socket connection", WSAGetLastError());
		}
		closesocket(socket);
	}),
	INVALID_SOCKET
>;

class RawSocket {
public:
	void set_is_nonblocking(bool const p_is_nonblocking) 
	{
		if (is_nonblocking_ != p_is_nonblocking) 
		{
			is_nonblocking_ = p_is_nonblocking;

			auto is_nonblocking = static_cast<u_long>(p_is_nonblocking);
			ioctlsocket(handle_.get(), FIONBIO, &is_nonblocking);
		}
	}
	[[nodiscard]]
	SOCKET get_winsock_handle() {
		return handle_.get();
	}

	void write(std::span<std::byte const> const data) 
	{
		if (is_closed_) {
			reconnect_();
		}

		if (::send(
				handle_.get(), 
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
		if (is_closed_) {
			return std::size_t{};
		}

		set_is_nonblocking(is_nonblocking);

		if (auto const receive_result = recv(
				handle_.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()), 
				0
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				is_closed_ = true;
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

	RawSocket(std::string_view const server, Port const port) :
		address_info_{get_address_info_(server, port)},
		handle_{create_handle_()}
	{}

private:
	using AddressInfo = std::unique_ptr<addrinfoW, decltype([](auto p){FreeAddrInfoW(p);})>;

	[[nodiscard]]
	static AddressInfo get_address_info_(std::string_view const server, Port const port) {
		auto const wide_server_name = utils::win::utf8_to_wide(server);
		auto const wide_port_string = std::to_wstring(port);
		auto const hints = addrinfoW{
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
		};
		auto address_info = static_cast<addrinfoW*>(nullptr);

		if (auto const result = GetAddrInfoW(
				wide_server_name.data(), 
				wide_port_string.data(), 
				&hints, 
				&address_info
			)) 
		{
			throw errors::ConnectionFailed{
				std::string("Failed to get address info for socket creation: ") + utils::win::get_error_message(result)//gai_strerror(result)
			};
		}

		return AddressInfo{address_info};
	}

	[[nodiscard]]
	SocketHandle create_handle_() const {
		auto const handle_error = [](auto const error_message) {
			if (auto const error_code = WSAGetLastError(); error_code != WSAEINPROGRESS) {
				utils::throw_connection_error(error_message, error_code);
			}
			constexpr auto time_to_wait_between_attempts = 1ms;
			std::this_thread::sleep_for(time_to_wait_between_attempts);
		};

		auto socket_handle = SocketHandle{};
		while ((socket_handle = socket(
				address_info_->ai_family, 
				address_info_->ai_socktype, 
				address_info_->ai_protocol
			)).get() == INVALID_SOCKET) 
		{
			handle_error("Failed to create socket");
		}

		while (connect(
				socket_handle.get(), 
				address_info_->ai_addr, 
				static_cast<int>(address_info_->ai_addrlen)
			) == SOCKET_ERROR)
		{
			handle_error("Failed to connect socket");
		}

		return socket_handle;
	}
	
	void reconnect_() {
		handle_ = create_handle_();
		is_closed_ = false;
	}

	WinSockLifetime api_lifetime_;
	AddressInfo address_info_;
	SocketHandle handle_;
	bool is_nonblocking_{false};
	bool is_closed_{false};
};

using DllHandle = utils::UniqueHandle<HMODULE, decltype([](auto h){ FreeLibrary(h); })>;

struct SspiLibrary {
	DllHandle dll_handle;

	PSecurityFunctionTableW functions;
	
	SspiLibrary() :
		dll_handle{LoadLibraryW(L"secur32.dll")} 
	{
		auto const throw_error = []{
			throw std::system_error{static_cast<int>(GetLastError()), std::system_category(), "Failed to initialize the SSPI library"};
		};
		
		if (!dll_handle) {
			throw_error();
		}
		
		// ew :)
		auto const init_security_interface = reinterpret_cast<INIT_SECURITY_INTERFACE_W>(
			reinterpret_cast<INT_PTR>(GetProcAddress(dll_handle.get(), "InitSecurityInterfaceW"))
		);

		if (!(functions = init_security_interface())) {
			throw_error();
		}
	}
	~SspiLibrary() = default;

	SspiLibrary(SspiLibrary const&) = delete;
	SspiLibrary& operator=(SspiLibrary const&) = delete;
	SspiLibrary(SspiLibrary&&) = delete;
	SspiLibrary& operator=(SspiLibrary&&) = delete;
};

auto const sspi_library = SspiLibrary{};

[[nodiscard]]
constexpr bool operator==(CredHandle const& first, CredHandle const& second) noexcept {
	return first.dwLower == second.dwLower && first.dwUpper == second.dwUpper;
}
[[nodiscard]]
constexpr bool operator!=(CredHandle const& first, CredHandle const& second) noexcept {
	return !(first == second);
}

[[nodiscard]]
constexpr bool operator==(SecBuffer const& first, SecBuffer const& second) noexcept {
	return first.pvBuffer == second.pvBuffer;
}
[[nodiscard]]
constexpr bool operator!=(SecBuffer const& first, SecBuffer const& second) noexcept {
	return !(first == second);
}

using SecurityContextHandle = utils::UniqueHandle<CtxtHandle, decltype([](auto& h){ sspi_library.functions->DeleteSecurityContext(&h); })>;

SecBufferDesc create_single_schannel_buffer_description(SecBuffer& buffer) {
	return {
		.ulVersion = SECBUFFER_VERSION,
		.cBuffers = 1ul,
		.pBuffers = &buffer,
	};
}
SecBufferDesc create_schannel_buffers_description(std::span<SecBuffer> const buffers) {
	return {
		.ulVersion = SECBUFFER_VERSION,
		.cBuffers = static_cast<unsigned long>(buffers.size()),
		.pBuffers = buffers.data(),
	};
}

/*
	Holds either received handshake data or TLS message data.
	The required size of the TLS handshake message buffer cannot be retrieved 
	through any API call. See the block comment in the class.
	After the handshake is complete, the buffer is resized because then the TLS message 
	header, trailer and message sizes can be retrieved using QueryContextAttributesW.
*/
class TlsMessageReceiveBuffer {
public:
	std::span<std::byte> extra_data;

	using iterator = utils::DataVector::iterator;

	[[nodiscard]]
	iterator begin() {
		return buffer_.begin();
	}
	[[nodiscard]]
	iterator end() {
		return buffer_.end();
	}

	void grow_to_size(std::size_t const new_size) {
		assert(new_size >= buffer_.size());
		
		if (!extra_data.empty()) {
			auto const extra_data_start = extra_data.data() - buffer_.data();
			assert(extra_data_start > 0 && extra_data_start < static_cast<std::ptrdiff_t>(buffer_.size()));
			buffer_.resize(new_size);
			extra_data = std::span{buffer_}.subspan(extra_data_start, extra_data.size());
		}
		else {
			buffer_.resize(new_size);
		}
	}
	[[nodiscard]]
	std::span<std::byte> get_full_buffer() {
		return buffer_;
	}

	[[nodiscard]]
	static TlsMessageReceiveBuffer allocate_new() {
		return TlsMessageReceiveBuffer{maximum_handshake_message_size};
	}

	TlsMessageReceiveBuffer() = default;
	~TlsMessageReceiveBuffer() = default;

	TlsMessageReceiveBuffer(TlsMessageReceiveBuffer const&) = delete;
	TlsMessageReceiveBuffer& operator=(TlsMessageReceiveBuffer const&) = delete;
	TlsMessageReceiveBuffer(TlsMessageReceiveBuffer&&) noexcept = default;
	TlsMessageReceiveBuffer& operator=(TlsMessageReceiveBuffer&&) noexcept = default;

private:
	/*
		When the buffer is too small to fit the whole handshake message received from the peer, the return 
		code from InitializeSecurityContextW is not SEC_E_INCOMPLETE_MESSAGE, but SEC_E_INVALID_TOKEN. 
		Trying to grow the buffer after getting that return code does not work. The server closes the 
		connection when trying to read more data afterwards. It seems that we need a fixed maximum 
		handshake message/token size.

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
	static constexpr auto maximum_handshake_message_size = std::size_t{1 << 14};

	utils::DataVector buffer_;
	
	explicit TlsMessageReceiveBuffer(std::size_t const size) :
		buffer_(size)
	{}
};

class SchannelConnectionInitializer {
public:
	/*
		Returns the resulting security context and a vector of any extra non-handshake data
		that should be processed as part of the next message.
	*/
	std::pair<SecurityContextHandle, TlsMessageReceiveBuffer> operator()() && {
		do_handshake_();
		return {std::move(security_context_), std::move(receive_buffer_)};
	}

	[[nodiscard]]
	SchannelConnectionInitializer(RawSocket* const socket, std::string_view const server) :
		socket_{socket},
		server_name_{utils::win::utf8_to_wide(server)}
	{}
	~SchannelConnectionInitializer() = default;

	SchannelConnectionInitializer(SchannelConnectionInitializer&&) noexcept = delete;
	SchannelConnectionInitializer& operator=(SchannelConnectionInitializer&&) noexcept = delete;
	SchannelConnectionInitializer(SchannelConnectionInitializer const&) = delete;
	SchannelConnectionInitializer& operator=(SchannelConnectionInitializer const&) = delete;

private:
	using CredentialsHandle = utils::UniqueHandle<CredHandle, decltype([](auto& h){ sspi_library.functions->FreeCredentialHandle(&h); })>;

	using HandshakeOutputBuffer = utils::UniqueHandle<
		SecBuffer, decltype([](auto const& buffer) {
			if (buffer.pvBuffer) {
				sspi_library.functions->FreeContextBuffer(buffer.pvBuffer);
			}
		})
	>;

	void do_handshake_() {
		if (auto const [return_code, output_buffer] = process_handshake_data_({});
			return_code != SEC_I_CONTINUE_NEEDED) // First call should always yield this return code.
		{
			utils::throw_connection_error("Schannel TLS handshake initialization failed", return_code, true);
		}
		else send_handshake_message_(output_buffer);

		auto offset = std::size_t{};
		while (true) {
			auto const read_span = read_response_(offset);
			if (auto const [return_code, output_buffer] = process_handshake_data_(read_span);
				return_code == SEC_I_CONTINUE_NEEDED)
			{
				if (output_buffer->cbBuffer) {
					send_handshake_message_(output_buffer);
				}
				offset = 0;
			}
			else if (return_code == SEC_E_INCOMPLETE_MESSAGE) {
				offset = read_span.size();
			}
			else if (return_code == SEC_E_OK) {
				return;
			}
			else {
				utils::throw_connection_error("Schannel TLS handshake failed", return_code);
			}
		}
	}
	
	/*
		Returns a span over the total read data.
	*/
	std::span<std::byte> read_response_(std::size_t const offset = {}) {
		auto const buffer_span = receive_buffer_.get_full_buffer();
		
		if (!receive_buffer_.extra_data.empty()) {
			assert(offset == 0);
			
			auto const extra_data_size = receive_buffer_.extra_data.size();
			std::ranges::copy_backward(receive_buffer_.extra_data, buffer_span.begin() + extra_data_size);

			receive_buffer_.extra_data = {};
			return buffer_span.first(extra_data_size);
		}
		else if (auto const read_result = socket_->read(buffer_span.subspan(offset));
			std::holds_alternative<ConnectionClosed>(read_result)) 
		{
			throw errors::ConnectionFailed{"The connection closed unexpectedly while reading handshake data.", true};
		}
		else {
			return buffer_span.subspan(0, offset + std::get<std::size_t>(read_result));
		}
	}

	struct [[nodiscard]] HandshakeProcessResult {
		SECURITY_STATUS status_code;
		HandshakeOutputBuffer output_buffer;
	};
	HandshakeProcessResult process_handshake_data_(std::span<std::byte> const input_buffer) {
		constexpr auto request_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
			ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

		// The second input buffer is used to indicate that extra data 
		// from the next message was at the end of the input buffer, 
		// and should be processed in the next call. There's not actually
		// any buffer pointer in that SecBuffer.
		auto input_buffers = std::array{
			SecBuffer{
				.cbBuffer = static_cast<unsigned long>(input_buffer.size()),
				.BufferType = SECBUFFER_TOKEN,
				.pvBuffer = input_buffer.data(),
			},
			SecBuffer{},
		};
		auto input_buffer_description = create_schannel_buffers_description(input_buffers);

		auto output_buffers = std::array{
			SecBuffer{.BufferType = SECBUFFER_TOKEN},
			SecBuffer{.BufferType = SECBUFFER_ALERT},
			SecBuffer{},
		};
		auto output_buffer_description = create_schannel_buffers_description(output_buffers);
		
		unsigned long returned_flags;

		auto const return_code = sspi_library.functions->InitializeSecurityContextW(
			&credentials_.get(),
			security_context_ ? &security_context_ : nullptr, // Null on first call, input security context handle
			server_name_.data(),
			request_flags,
			0, // Reserved
			0, // Not used with Schannel
			input_buffer.empty() ? nullptr : &input_buffer_description, // Null on first call
			0, // Reserved
			&security_context_, // Output security context handle
			&output_buffer_description,
			&returned_flags,
			nullptr // Don't care about expiration date right now
		);

		if (returned_flags != request_flags) {
			utils::throw_connection_error("The schannel security context flags were not supported");
		}

		return HandshakeProcessResult{[&]{
			if (input_buffers[1].BufferType == SECBUFFER_EXTRA) {
				receive_buffer_.extra_data = input_buffer.last(input_buffers[1].cbBuffer);
			}
			
			if (return_code == SEC_I_COMPLETE_AND_CONTINUE || return_code == SEC_I_COMPLETE_NEEDED) {
				sspi_library.functions->CompleteAuthToken(&security_context_, &output_buffer_description);

				if (return_code == SEC_I_COMPLETE_AND_CONTINUE) {
					return SEC_I_CONTINUE_NEEDED;
				}
				return SEC_E_OK;
			}
			return return_code;
		}(), HandshakeOutputBuffer{output_buffers[0]}};
	}
	void send_handshake_message_(HandshakeOutputBuffer const& message_buffer) {
		socket_->write(std::span{
			static_cast<std::byte const*>(message_buffer->pvBuffer), 
			static_cast<std::size_t>(message_buffer->cbBuffer)
		});
	}

	[[nodiscard]]
	static CredentialsHandle aquire_credentials_handle_() {
		auto credentials_data = SCHANNEL_CRED{
			.dwVersion = SCHANNEL_CRED_VERSION,
		};
		CredHandle credentials_handle;
		TimeStamp credentials_time_limit;
		
		auto const security_status = sspi_library.functions->AcquireCredentialsHandleW(
			nullptr,
			UNISP_NAME_W,
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

	CredentialsHandle credentials_{aquire_credentials_handle_()};
	RawSocket* socket_;
	std::wstring server_name_;

	SecurityContextHandle security_context_;
	TlsMessageReceiveBuffer receive_buffer_{TlsMessageReceiveBuffer::allocate_new()};
};

class TlsSocket {
public:
	void write(std::span<std::byte const> data) {
		while (!data.empty()) {
			auto const message_length = std::min(data.size(), static_cast<std::size_t>(stream_sizes_.cbMaximumMessage));

			auto const output_buffer = encrypt_message_(data.first(message_length));
			raw_socket_->write(output_buffer);

			data = data.subspan(message_length);
		}
	}

	[[nodiscard]]
	auto read(std::span<std::byte> const buffer, bool const is_nonblocking = false) 
		-> std::variant<ConnectionClosed, std::size_t>
	{
		if (decrypted_message_left_.empty()) {
			auto const receive_buffer_span = receive_buffer_.get_full_buffer();
			auto read_offset = std::size_t{};
			
			while (true) {
				if (auto const read_result = read_encrypted_data_(read_offset, is_nonblocking);
					std::holds_alternative<ConnectionClosed>(read_result))
				{
					return read_result;
				}
				else if (decrypt_message_(receive_buffer_span.first(read_offset + std::get<std::size_t>(read_result)))
					|| is_nonblocking)
				{
					break;
				}
				else {
					read_offset += std::get<std::size_t>(read_result);
				}
			}
		}
		if (decrypted_message_left_.empty()) {
			return std::size_t{};
		}
		
		auto const size = std::min(decrypted_message_left_.size(), buffer.size());
		std::ranges::copy(decrypted_message_left_.first(size), buffer.begin());
		decrypted_message_left_ = decrypted_message_left_.subspan(size);
		
		return size;
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		return read(buffer, true);
	}

	TlsSocket(std::string_view const server, Port const port) 
	{
		initialize_connection_(server, port);
	}

private:
	void initialize_connection_(std::string_view const server, Port const port) {
		if (raw_socket_) {
			return;
		}

		raw_socket_ = std::make_unique<RawSocket>(server, port);

		std::tie(security_context_, receive_buffer_) = SchannelConnectionInitializer{raw_socket_.get(), server}();
		initialize_stream_sizes_();
	}

	void initialize_stream_sizes_() {
		if (auto const result = sspi_library.functions->QueryContextAttributesW(&security_context_, SECPKG_ATTR_STREAM_SIZES, &stream_sizes_);
			result != SEC_E_OK) 
		{
			utils::throw_connection_error("Failed to query Schannel security context stream sizes", result, true);
		}
		receive_buffer_.grow_to_size(stream_sizes_.cbHeader + stream_sizes_.cbMaximumMessage + stream_sizes_.cbTrailer);
	}

	[[nodiscard]]
	utils::DataVector encrypt_message_(std::span<std::byte const> const data) {
		// https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage

		auto full_buffer = utils::DataVector(stream_sizes_.cbHeader + data.size() + stream_sizes_.cbTrailer);
		std::ranges::copy(data, full_buffer.begin() + stream_sizes_.cbHeader);
		
		auto buffers = std::array{
			SecBuffer{
				.cbBuffer = stream_sizes_.cbHeader,
				.BufferType = SECBUFFER_STREAM_HEADER,
				.pvBuffer = full_buffer.data(),
			},
			SecBuffer{
				.cbBuffer = static_cast<unsigned long>(data.size()),
				.BufferType = SECBUFFER_DATA,
				.pvBuffer = full_buffer.data() + stream_sizes_.cbHeader,
			},
			SecBuffer{
				.cbBuffer = stream_sizes_.cbTrailer,
				.BufferType = SECBUFFER_STREAM_TRAILER,
				.pvBuffer = full_buffer.data() + stream_sizes_.cbHeader + data.size(),
			},
			// Empty buffer that must be supplied at the end.
			SecBuffer{},
		};

		auto buffers_description = create_schannel_buffers_description(buffers);

		if (auto const result = sspi_library.functions->EncryptMessage(&security_context_, 0, &buffers_description, 0);
			result != SEC_E_OK) 
		{
			utils::throw_connection_error("Failed to encrypt TLS message", result, true);
		}

		return full_buffer;
	}

	[[nodiscard]]
	auto read_encrypted_data_(std::size_t const offset, bool const is_nonblocking) 
		-> std::variant<ConnectionClosed, std::size_t>
	{
		auto const buffer_span = receive_buffer_.get_full_buffer();
		
		if (!receive_buffer_.extra_data.empty()) {
			assert(offset == 0);
			
			auto const extra_data_size = receive_buffer_.extra_data.size();
			std::ranges::copy_backward(receive_buffer_.extra_data, buffer_span.begin() + extra_data_size);

			receive_buffer_.extra_data = {};
			return extra_data_size;
		}
		else {
			return raw_socket_->read(buffer_span.subspan(offset), is_nonblocking);
		}
	}

	// Returns false if the encrypted message was incomplete
	[[nodiscard]]
	bool decrypt_message_(std::span<std::byte> const message) {
		// https://docs.microsoft.com/en-us/windows/win32/secauthn/stream-contexts
		auto buffers = std::array{
			SecBuffer{ // This will hold the message header afterwards
				.cbBuffer = static_cast<unsigned long>(message.size()),
				.BufferType = SECBUFFER_DATA,
				.pvBuffer = message.data(),
			},
			SecBuffer{}, // Will hold the decrypted data
			SecBuffer{}, // Will hold the message trailer
			SecBuffer{}, // May hold size of extra undecrypted data (from the next message)
		};
		auto message_buffer_description = create_schannel_buffers_description(buffers);

		if (auto const status_code = sspi_library.functions->DecryptMessage(&security_context_, &message_buffer_description, 0, nullptr);
			status_code == SEC_E_OK)
		{
			decrypted_message_left_ = {static_cast<std::byte const*>(buffers[1].pvBuffer), static_cast<std::size_t>(buffers[1].cbBuffer)};

			// https://docs.microsoft.com/en-us/windows/win32/secauthn/extra-buffers-returned-by-schannel
			// Data from the next message. Always at the end.
			if (buffers[3].BufferType == SECBUFFER_EXTRA) {
				receive_buffer_.extra_data = message.last(buffers[3].cbBuffer);
			}
			return true;
		}
		else if (status_code == SEC_E_INCOMPLETE_MESSAGE) {
			return false;
		}
		else {
			utils::throw_connection_error("Failed to decrypt a received TLS message", status_code, true);
		}
	}

	std::unique_ptr<RawSocket> raw_socket_;

	SecurityContextHandle security_context_;
	
	SecPkgContext_StreamSizes stream_sizes_;

	TlsMessageReceiveBuffer receive_buffer_;

	// This is the part of the message buffer that contains the 
	// rest of the decrypted message data that has not been read yet.
	std::span<std::byte const> decrypted_message_left_;
};

#endif // _WIN32

#ifdef IS_POSIX

using PosixSocketHandle = int;

using SocketHandle = utils::UniqueHandle<
	PosixSocketHandle, 
	decltype([](auto const handle) {
		if (::shutdown(handle, SHUT_RDWR) == -1) {
			utils::throw_connection_error("Failed to shut down socket connection");
		}
		::close(handle);		
	}),
	PosixSocketHandle{-1}
>;

class RawSocket {
public:
	void make_nonblocking() {
		if (!is_nonblocking_) {
			auto const flags = fcntl(handle_.get(), F_GETFL);
			if (-1 == fcntl(handle_.get(), F_SETFL, flags | O_NONBLOCK)) {
				utils::throw_connection_error("Failed to turn on nonblocking mode on socket");
			}
			is_nonblocking_ = true;
		}
	}
	void make_blocking() {
		if (is_nonblocking_) {
			auto const flags = fcntl(handle_.get(), F_GETFL);
			if (-1 == fcntl(handle_.get(), F_SETFL, flags & ~O_NONBLOCK)) {
				utils::throw_connection_error("Failed to turn off nonblocking mode on socket");
			}
			is_nonblocking_ = false;
		}
	}
	[[nodiscard]]
	PosixSocketHandle get_posix_handle() const {
		return handle_.get();
	}
	
	void reconnect_() {
		handle_ = create_handle_();
		is_closed_ = false;
	}

	void write(std::span<std::byte const> const data) {
		if (is_closed_) {
			reconnect_();
		}

		if (::send(
				handle_.get(),
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
		if (is_closed_) {
			return std::size_t{};
		}

		if (auto const receive_result = recv(
				handle_.get(), 
				reinterpret_cast<char*>(buffer.data()), 
				static_cast<int>(buffer.size()),
				is_nonblocking ? MSG_DONTWAIT : 0
			); receive_result >= 0)
		{
			if (receive_result == 0) {
				is_closed_ = true;
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
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t>
	{
		return read(buffer, true);
	}

	RawSocket(std::string_view const server, Port const port) :
		address_info_{get_address_info_(std::string{server}, port)}, 
		handle_{create_handle_()}
	{}

private:
	using AddressInfo = std::unique_ptr<addrinfo, decltype([](auto const p){freeaddrinfo(p);})>;

	[[nodiscard]]
	static AddressInfo get_address_info_(std::string const server, Port const port) {
		auto const port_string = std::to_string(port);
		auto const hints = addrinfo{
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
		};
		auto address_info = static_cast<addrinfo*>(nullptr);

		if (auto const result = ::getaddrinfo(
				reinterpret_cast<char const*>(server.data()),
				port_string.data(),
				&hints, 
				&address_info
			))
		{
			throw errors::ConnectionFailed{
				std::string("Failed to get address info for socket creation: ") + gai_strerror(result)
			};
		}

		return AddressInfo{address_info};
	}

	[[nodiscard]]
	SocketHandle create_handle_() const {
		auto socket_handle = SocketHandle{::socket(
			address_info_->ai_family, 
			address_info_->ai_socktype, 
			address_info_->ai_protocol
		)};
		if (!socket_handle) {
			utils::throw_connection_error("Failed to create socket");
		}

		while (::connect(
				socket_handle.get(), 
				address_info_->ai_addr, 
				static_cast<int>(address_info_->ai_addrlen)
			) == -1)
		{
			if (auto const error_code = errno; error_code != EINPROGRESS) {
				utils::throw_connection_error("Failed to connect socket", error_code);
			}
			constexpr auto time_to_wait_between_attempts = 1ms;
			std::this_thread::sleep_for(time_to_wait_between_attempts);
		}

		return socket_handle;
	}

	AddressInfo address_info_;

	SocketHandle handle_;

	bool is_nonblocking_{false};

	bool is_closed_{false};
};

class TlsSocket {
public:
	void write(std::span<std::byte const> const data) {
		ensure_connected_();
		
		if (SSL_write(
				tls_connection_.get(),
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
		if (is_closed_) {
			return std::size_t{};
		}
		
		raw_socket_->make_blocking();
		if (auto const read_result = SSL_read(
				tls_connection_.get(),
				buffer.data(),
				static_cast<int>(buffer.size())
			); read_result >= 0) 
		{
			if (read_result == 0) {
				is_closed_ = true;
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
		if (is_closed_) {
			return std::size_t{};
		}
		
		raw_socket_->make_nonblocking();
		if (auto const read_result = SSL_read(
				tls_connection_.get(),
				buffer.data(),
				static_cast<int>(buffer.size())
			); read_result > 0)
		{
			return static_cast<std::size_t>(read_result);
		}
		else switch (auto const error_code = SSL_get_error(tls_connection_.get(), read_result)) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				// No available data to read at the moment.
				return std::size_t{};
			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_SYSCALL:
				if (errno == 0) {
					is_closed_ = true;
					// Peer shut down the connection.
					return ConnectionClosed{};
				}
				[[fallthrough]];
			default:
				utils::throw_connection_error("Failed to read available data from socket", error_code);
		}
		utils::unreachable();
	}

	TlsSocket(std::string_view const server, Port const port) {
		initialize_connection_(server, port);
	}

private:
	using TlsContext = std::unique_ptr<SSL_CTX, decltype([](auto x){SSL_CTX_free(x);})>;
	using TlsConnection = std::unique_ptr<SSL, decltype([](auto x){SSL_free(x);})>;

	static void throw_tls_error_() {
		throw errors::ConnectionFailed{utils::unix::get_openssl_error_string(), true};
	}

	void ensure_connected_() {
		if (is_closed_) {
			raw_socket_->reconnect_();
			update_tls_socket_handle_();
			// connect_();
		}
	}

	void initialize_connection_(std::string_view const server, Port const port) {
		if (raw_socket_) {
			return;
		}

		configure_tls_context_();
		configure_tls_connection_(std::string{server}, port);
		connect_();
	}
	
	void configure_tls_context_() {
		// SSL_CTX_set_options(tls_context_.get(), SSL_OP_ALL);

		if (1 != SSL_CTX_set_default_verify_paths(tls_context_.get())) {
			throw_tls_error_();
		}
		SSL_CTX_set_read_ahead(tls_context_.get(), true);
	}

	void configure_tls_connection_(std::string const server, Port const port) {
		auto const host_name_c_string = server.data();

		// For SNI (Server Name Identification)
		// The macro casts the string to a void* for some reason. Ew.
		// The casts are to suppress warnings about it.
		if (1 != SSL_set_tlsext_host_name(tls_connection_.get(), reinterpret_cast<void*>(const_cast<char*>(host_name_c_string)))) {
			throw_tls_error_();
		}
		// Configure automatic hostname check
		if (1 != SSL_set1_host(tls_connection_.get(), host_name_c_string)) {
			throw_tls_error_();
		}

		// Set the socket to be used by the tls connection
		raw_socket_ = std::make_unique<RawSocket>(server, port);
		update_tls_socket_handle_();
	}

	void update_tls_socket_handle_() {
		if (1 != SSL_set_fd(tls_connection_.get(), raw_socket_->get_posix_handle())) {
			throw_tls_error_();
		}
	}

	void connect_() {
		SSL_connect(tls_connection_.get());

		// Just to check that a certificate was presented by the server
		if (auto const certificate = SSL_get_peer_certificate(tls_connection_.get())) {
			X509_free(certificate);
		}
		else throw_tls_error_();

		// Get result of the certificate verification
		auto const verify_result = SSL_get_verify_result(tls_connection_.get());
		if (X509_V_OK != verify_result) {
			throw_tls_error_();
		}
	}

	std::unique_ptr<RawSocket> raw_socket_;
	bool is_closed_{false};

	TlsContext tls_context_ = []{
		if (auto const method = TLS_client_method()) {
			if (auto const tls = SSL_CTX_new(method)) {
				return TlsContext{tls};
			}
		}
		throw_tls_error_();
		return TlsContext{};
	}();

	TlsConnection tls_connection_ = [this]{
		if (auto const tls_connection = SSL_new(tls_context_.get())) {
			return TlsConnection{tls_connection};
		}
		throw_tls_error_();
		return TlsConnection{};
	}();
};
#endif // IS_POSIX

class Socket::Implementation {
public:
	void write(std::span<std::byte const> const buffer) {
		if (std::holds_alternative<RawSocket>(socket_)) {
			std::get<RawSocket>(socket_).write(buffer);
		}
		else std::get<TlsSocket>(socket_).write(buffer);
	}
	[[nodiscard]]
	auto read(std::span<std::byte> const buffer)
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		if (std::holds_alternative<RawSocket>(socket_)) {
			return std::get<RawSocket>(socket_).read(buffer);
		}
		return std::get<TlsSocket>(socket_).read(buffer);
	}
	[[nodiscard]]
	auto read_available(std::span<std::byte> const buffer) 
		-> std::variant<ConnectionClosed, std::size_t> 
	{
		if (std::holds_alternative<RawSocket>(socket_)) {
			return std::get<RawSocket>(socket_).read_available(buffer);
		}
		return std::get<TlsSocket>(socket_).read_available(buffer);
	}

	Implementation(std::string_view const server, Port const port, bool const is_tls_encrypted) :
		socket_{select_socket_(server, port, is_tls_encrypted)}
	{}

private:
	using SocketVariant = std::variant<RawSocket, TlsSocket>;

	[[nodiscard]]
	static SocketVariant select_socket_(std::string_view const server, Port const port, bool const is_tls_encrypted)
	{
		if (port == utils::get_port(Protocol::Https) || is_tls_encrypted) {
			return TlsSocket{server, port};
		}
		return RawSocket{server, port};
	}

	SocketVariant socket_;
};

void Socket::write(std::span<std::byte const> data) const {
	implementation_->write(data);
}

auto Socket::read(std::span<std::byte> buffer) const 
	-> std::variant<ConnectionClosed, std::size_t> 
{
	return implementation_->read(buffer);
}

auto Socket::read_available(std::span<std::byte> buffer) const 
	-> std::variant<ConnectionClosed, std::size_t> 
{
	return implementation_->read_available(buffer);
}

Socket::Socket(std::string_view const server, Port const port, bool const is_tls_encrypted) :
	implementation_{std::make_unique<Implementation>(server, port, is_tls_encrypted)}
{}
Socket::~Socket() = default;

Socket::Socket(Socket&&) noexcept = default;
Socket& Socket::operator=(Socket&&) noexcept = default;

} // namespace internet_client
