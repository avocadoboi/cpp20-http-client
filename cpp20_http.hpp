#pragma once

#include <fstream>
#include <functional>
#include <string>
#include <string_view>
#include <span>
#include <ranges>
#include <concepts>

namespace http {
	/*
		This is everything that doesn't have anything to do with http specifically, 
		but are utilities that are used within the library.
	*/
	namespace util {
		/*
			This is a concept that compiles for AnyOf<T, U, V, W, ...> where T is equal to any of U, V, W, ...
		*/
		template<typename T, typename ... U>
		concept AnyOf = (std::is_same_v<T, U> || ...);

		template<typename T>
		constexpr auto select_on_type(T&& p_item) -> auto&& {
			return std::forward<T>(p_item);
		}

		/*
			Selects a variable from the argument list based on 
			its type, which is given as a template argument.
		*/
		template<typename T, typename U, typename ... V>
		constexpr auto select_on_type(U&& p_first_item, V&& ... p_items) -> auto&&
			requires AnyOf<T, U, V...>
		{
			if constexpr (std::is_same_v<T, U>) {
				return std::forward<U>(p_first_item);
			}
			else {
				return select_on_type<T>(std::forward<V>(p_items)...);
			}
		}
		
		//---------------------------------------------------------

		/*
			Converts a std::u8string_view to a std::string_view,
			by using the same exact bytes; there's no encoding
			conversion here. The returned std::string_view points
			to the same data, and is thus utf-8 encoded as well.
			This is only meant to be used to interoperate
			with APIs that assume regular strings to be utf-8 
			encoded.
		*/
		[[nodiscard]] inline constexpr auto u8string_to_utf8_string(
			std::u8string_view const p_u8string
		) noexcept -> std::string_view 
		{
			return std::string_view{
				// I think this is ok because all we're doing is telling the 
				// compiler to pretend the bytes are char instead of char8_t,
				// which is the intended behavior. The encoding should still
				// be utf-8.
				reinterpret_cast<char const*>(p_u8string.data()), 
				p_u8string.size(),
			};
		}
		/*
			The reverse of u8string_to_utf8_string.
		*/
		[[nodiscard]] inline constexpr auto utf8_string_to_u8string(
			std::string_view const p_utf8_string
		) noexcept-> std::u8string_view 
		{
			return std::u8string_view{
				reinterpret_cast<char8_t const*>(p_utf8_string.data()),
				p_utf8_string.size(),
			};
		}
	}

	//---------------------------------------------------------

	/*
		A minimal collection of internet related errors you should catch and handle yourself.
		They do not inherit from std::exception because these are made to be catched separately
		and do not have default error messages. It's your responsibility to provide useful
		error messages to the user and/or proper error handling.
	*/
	namespace error {
		struct InvalidUrl {};
		struct ItemNotFound {};

		enum class ConnectionFailed {
			NoInternet, // There was no internet connection
			Timeout, // The connection timed out
			Shutdown, // The connection was shut down
		};
	}

	//---------------------------------------------------------

	/*
		This is a concept representing any UTF-8 or UTF-16 character code point.
		It compiles for char, char8_t, char16_t or wchar_t character types.
	*/
	template<typename T>
	concept Character = util::AnyOf<T, char, char8_t, char16_t, wchar_t>;


	/*
		The result of the split_url function.
	*/
	template<Character _Char>
	struct SplitUrl {
		std::basic_string_view<_Char> domain_name, path;
	};

	/*
		Splits an URL into a server/domain name and file path.
	*/
	template<Character _Char>
	constexpr auto split_url(std::basic_string_view<_Char> const p_url) noexcept 
		-> SplitUrl<_Char> 
	{
		if (p_url.empty()) {
			return {};
		}
		
		constexpr auto forward_slash = util::select_on_type<_Char>('/', u8'/', u'/', L'/');
		constexpr auto colon = util::select_on_type<_Char>(':', u8':', u':', L':');
		
		constexpr auto minimum_split_pos = size_t{2};
		
		auto start_pos = size_t{};
		do {
			auto const pos = p_url.find(forward_slash, !start_pos ? minimum_split_pos : start_pos);
			if (pos == std::string_view::npos) {
				return {p_url.substr(start_pos), {}};
			}
			else if (auto const last = p_url[pos - 1];
				last != colon && last != forward_slash) 
			{
				return {p_url.substr(start_pos, pos - start_pos), p_url.substr(pos)};
			}
			else {
				start_pos = pos + 1;
			}
		} while (true);
	}

	//---------------------------------------------------------

	struct GetResponse {
		std::vector<std::byte> content;

		auto content_as_text() const noexcept -> std::u8string_view {
			return std::u8string_view{reinterpret_cast<char8_t const*>(content.data()), content.size()};
		}
		auto write_to_file(std::string const& p_file_name) const -> void {
			auto file_stream = std::ofstream{p_file_name.data(), std::ios::binary};
			file_stream.write(reinterpret_cast<char const*>(content.data()), content.size());
		}
	};

	class AsyncGetRequest {

	};

	/*

	*/
	struct HeaderCopy {
		std::u8string name, value;
	};
	/*
	*/
	struct Header {
		std::u8string_view name, value;
	};

	class GetRequest {
	private:
		class Implementation;
		std::unique_ptr<Implementation> m_implementation;

	public:
		~GetRequest();

		/*
			Sets the name of the application that is sending the HTTP request.
			The default value is 
		*/
		auto set_user_agent(std::u8string_view p_user_agent) -> GetRequest&;

		auto add_headers(std::u8string_view p_headers) -> GetRequest&;
		auto add_headers(std::span<Header const> const p_headers) -> GetRequest& {
			auto headers_string = std::u8string{};
			headers_string.reserve(p_headers.size()*128);
			for (auto const header : p_headers) {
				// TODO: Use std::format when it has been implemented by compilers.
				(((headers_string += header.name) += u8": ") += header.value) += '\n';
			}
			return add_headers(headers_string);
		}
		auto add_headers(std::initializer_list<Header const> const p_headers) -> GetRequest& {
			return add_headers(std::span{p_headers});
		}
		auto add_header(Header p_header) -> GetRequest& {
			return add_headers(((std::u8string{p_header.name} += u8": ") += p_header.value) += u8"\n");
		}

	// private:
		// std::function<void(GetResponse&&)> m_response_handler;
	
	// public:
		// template<std::invocable<void(GetResponse&&)> _Handler>
		// [[nodiscard]] auto set_response_listener(_Handler&& p_handler) -> AsyncGetRequest {
		// 	m_response_handler = std::move(p_handler);
		// }

		// auto set_status_listener()

		[[nodiscard]] auto send() -> GetResponse;

	private:
		friend auto get(std::u8string_view p_url) -> GetRequest;
		GetRequest(std::u8string_view p_url);
	};
	
	/*
		Creates a get request.
	*/
	[[nodiscard]] inline auto get(std::u8string_view p_url) -> GetRequest {
		return GetRequest{p_url};
	} 
}
