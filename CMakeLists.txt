cmake_minimum_required(VERSION 3.18.0)
project(Cpp20HttpClient VERSION 2.1.1 LANGUAGES CXX)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin/)

# Project specific options
option(CPP20_HTTP_CLIENT_BUILD_EXAMPLES "Set to OFF to not build examples" ON)
option(CPP20_HTTP_CLIENT_BUILD_TESTS "Set to OFF to not build tests" ON)
option(CPP20_HTTP_CLIENT_ENABLE_INSTALL "Generate the install target" ON)

#-----------------------------
# Library target.

add_library(cpp20_http_client STATIC source/cpp20_http_client.cpp)
add_library(Cpp20HttpClient::cpp20_http_client ALIAS cpp20_http_client)

set_target_properties(cpp20_http_client PROPERTIES CXX_EXTENSIONS OFF)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	add_compile_options(/utf-8)
	# Concepts are (or were) only available in /std:c++latest, not in /std:c++20
	target_compile_options(cpp20_http_client PUBLIC /std:c++latest)
else ()
	target_compile_features(cpp20_http_client PUBLIC cxx_std_20)
endif ()

target_include_directories(cpp20_http_client PUBLIC 
	# When using the library from the install tree, relative paths can be used.
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

if (WIN32)
	# Windows sockets 2 and Schannel.
	target_link_libraries(cpp20_http_client PRIVATE Ws2_32 crypt32)
else ()
	# OpenSSL.
	find_package(OpenSSL REQUIRED)
	target_include_directories(cpp20_http_client PRIVATE "${OPENSSL_INCLUDE_DIR}/../")
	target_link_libraries(cpp20_http_client PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
endif ()

#-----------------------------

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	include(CTest)
	if (BUILD_TESTING AND CPP20_HTTP_CLIENT_BUILD_TESTS)
		add_subdirectory(tests)
	endif ()
endif ()

if (CPP20_HTTP_CLIENT_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif ()

#-----------------------------
# Set up installation.

include(CMakePackageConfigHelpers)

if (CPP20_HTTP_CLIENT_ENABLE_INSTALL)
	# Create a file that contains information about package versioning.
	# It will be placed in CMAKE_CURRENT_BINARY_DIR.
	write_basic_package_version_file(
		${PROJECT_NAME}ConfigVersion.cmake
		VERSION ${PROJECT_VERSION}
		COMPATIBILITY AnyNewerVersion
	)
	# During installation, the version file will be installed.
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
		DESTINATION lib/cmake/${PROJECT_NAME}) # Relative to the installation path.
	
	set(TARGET_EXPORT_NAME ${PROJECT_NAME}Targets)
	
	# Specifies the target(s) that will be installed, and where to install 
	# the compiled library (relative to package installation path ${CMAKE_INSTALL_PREFIX}).
	install(
		TARGETS cpp20_http_client
		EXPORT ${TARGET_EXPORT_NAME} 
		ARCHIVE DESTINATION lib
	)
		
	# During installation, a target configuration file will be exported to a *Targets.cmake file
	# that is included by the *Config.cmake.in file which finds the dependencies of the library.
	install(
		EXPORT ${TARGET_EXPORT_NAME}
		FILE ${TARGET_EXPORT_NAME}.cmake
		NAMESPACE ${PROJECT_NAME}::
		DESTINATION lib/cmake/${PROJECT_NAME} # Relative to installation path
	)
	
	# This uses the *Config.cmake.in file to generate a *Config.cmake file with 
	# the variables specified by PATH_VARS inserted.
	configure_package_config_file(
		cmake/${PROJECT_NAME}Config.cmake.in
		${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
		INSTALL_DESTINATION lib/cmake/${PROJECT_NAME}
		PATH_VARS TARGET_EXPORT_NAME
	)
	
	# Install the config file 
	install(
		FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
		DESTINATION lib/cmake/${PROJECT_NAME}
	)
	
	install(DIRECTORY include DESTINATION .)
endif ()
