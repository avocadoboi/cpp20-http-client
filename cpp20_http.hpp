#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <concepts>
#include <functional>
#include <fstream>

namespace http {
	namespace error {
		struct InvalidUrl {};
		struct ItemNotFound {};
		struct ConnectionTimeout {};
		struct ConnectionShutdown {};
	}

	//---------------------------------------------------------

	template<typename T>
	concept Character = std::is_same_v<T, char8_t> || 
		std::is_same_v<T, char16_t> || 
		std::is_same_v<T, wchar_t>;

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

		constexpr auto select_character = [](char8_t u8, char16_t u16, wchar_t wide) {
			if constexpr (std::is_same_v<_Char, char8_t>) {
				return u8;
			}
			if constexpr (std::is_same_v<_Char, char16_t>) {
				return u16;
			}
			if constexpr (std::is_same_v<_Char, wchar_t>) {
				return wide;
			}
		};
		
		constexpr auto forward_slash = select_character(u8'/', u'/', L'/');
		constexpr auto colon = select_character(u8':', u':', L':');
		
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
		auto write_to_file(std::string const& p_file_name) const {
			auto file_stream = std::ofstream{p_file_name.data(), std::ios::binary};
			file_stream.write(reinterpret_cast<char const*>(content.data()), content.size());
		}
	};

	class AsyncGetRequest {

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

		auto set_headers(std::u8string_view p_headers) -> GetRequest&;

		// auto add_header(std::u8string_view p_name, std::u8string_view p_value) -> GetRequest&;

		// auto add_header(std::u8string_view p_header) -> GetRequest&;

	// private:
		// std::function<void(GetResponse&&)> m_response_handler;
	
	// public:
		// template<std::invocable<void(GetResponse&&)> _Handler>
		// [[nodiscard]] auto set_response_listener(_Handler&& p_handler) -> AsyncGetRequest {
		// 	m_response_handler = std::move(p_handler);
		// }

		// auto set_status_listener()

		auto send() -> GetResponse;

	private:
		friend auto get(std::u8string_view p_url) -> GetRequest;
		GetRequest(std::u8string_view p_url);
	};
	
	[[nodiscard]] inline auto get(std::u8string_view p_url) -> GetRequest {
		return GetRequest{p_url};
	} 
}
