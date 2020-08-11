#pragma once

#include <string_view>
#include <memory>
#include <functional>
#include <concepts>

namespace http {
	class GetResponse {
		std::vector<std::byte> content;

		auto content_as_text() noexcept -> std::u8string_view {
			return std::u8string_view{reinterpret_cast<char8_t const*>(content.data()), content.size()};
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
