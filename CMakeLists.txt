cmake_minimum_required(VERSION 3.18.0)
project(Cpp20InternetClient VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin/)

#-----------------------------
# Library target.

add_library(cpp20_internet_client STATIC source/cpp20_internet_client.cpp)
add_library(Cpp20InternetClient::cpp20_internet_client ALIAS cpp20_internet_client)

target_compile_features(cpp20_internet_client PUBLIC cxx_std_20)
set_target_properties(cpp20_internet_client PROPERTIES CXX_EXTENSIONS off)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	target_compile_options(cpp20_internet_client PUBLIC
		/experimental:external
		/external:anglebrackets
		/external:W0 
		/WX /Wall
	)
else()
	target_compile_options(cpp20_internet_client PUBLIC
		-Werror -Wall -Wpedantic -Wextra 
		-Wimplicit-fallthrough=5 
		-Wduplicated-branches -Wduplicated-cond 
		-Wcast-qual -Wconversion
		
		-Wno-parentheses
		-Wno-missing-field-initializers
	)
endif()

target_include_directories(cpp20_internet_client PUBLIC 
	# When using the library from the install tree, relative paths can be used.
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

if (WIN32)
	# Windows sockets 2 and Schannel.
	target_link_libraries(cpp20_internet_client PRIVATE Ws2_32 crypt32)
else ()
	# OpenSSL.
	find_package(OpenSSL REQUIRED)
	target_include_directories(cpp20_internet_client PUBLIC "${OPENSSL_INCLUDE_DIR}/../")
	target_link_libraries(cpp20_internet_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif ()

#-----------------------------

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	include(CTest)
	if (BUILD_TESTING)
		add_subdirectory(tests)
	endif ()
endif ()

if (NOT BUILD_TESTING)
	add_subdirectory(examples)
endif ()

#-----------------------------
# Set up installation.

include(CMakePackageConfigHelpers)

# Create a file that contains information about package versioning.
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
	TARGETS cpp20_internet_client
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
