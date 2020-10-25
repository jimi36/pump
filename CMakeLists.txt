CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Specifies compilers on linux
IF(UNIX)
	SET(CMAKE_C_COMPILER gcc)
	SET(CMAKE_CXX_COMPILER g++)
ENDIF()

PROJECT(pump_main)

SET(pump_MAJOR_VERSION 1)
SET(pump_MINOR_VERSION 2)
SET(pump_BUILD_VERSION 13)

# Specifies root dir
SET(ROOT_DIR ${PROJECT_SOURCE_DIR})

# Append cmake module path
LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Option build debug (default OFF)
OPTION(BUILD_DEBUG "Option build debug" OFF)
INCLUDE(option_build)

# Option build with iocp, only for windows (default ON)
OPTION(WITH_IOCP "Option build with iocp, only for windows" ON)
INCLUDE(option_iocp)

# Option build with jemalloc (default OFF)
OPTION(WITH_JEMALLOC "Option build with jemalloc" OFF)
INCLUDE(option_jemalloc)

# Option build with TLS [DISABLE OPENSSL GNUTLS] (default DISABLE)
SET(WITH_TLS DISABLE)
INCLUDE(option_tls)

# Load compile flags
INCLUDE(option_cflags)

# Build pump
INCLUDE(build_pump)

# Build pump test
INCLUDE(build_pump_test)
