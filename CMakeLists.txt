CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Specifies compiler
IF(UNIX)
	SET(CMAKE_C_COMPILER gcc)
	SET(CMAKE_CXX_COMPILER g++)
ENDIF()

PROJECT(pump_main)

SET(pump_MAJOR_VERSION 1)
SET(pump_MINOR_VERSION 3)
SET(pump_BUILD_VERSION 3)

# Specifies root dir
SET(ROOT_DIR ${PROJECT_SOURCE_DIR})

CMAKE_POLICY(PUSH)
#CMAKE_POLICY(SET CMP0054 OLD)

# Include cmake functions
INCLUDE(TestBigEndian)
INCLUDE(CheckIncludeFile)
#INCLUDE(CheckSymbolExists)
#INCLUDE(CheckLibraryExists)
INCLUDE(CheckFunctionExists)
#INCLUDE(CheckStructHasMember)

# Append cmake module path
LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Option build debug (default OFF)
OPTION(BUILD_DEBUG "Option build debug" OFF)

# Option build with iocp, only for windows (default ON)
OPTION(WITH_IOCP "Option build with iocp, only for windows" ON)

# Option build with jemalloc (default OFF)
OPTION(WITH_JEMALLOC "Option build with jemalloc" OFF)

# Option build with TLS (default OFF)
OPTION(WITH_TLS "Option build with tls" ON)

# Option build with test (default ON)
OPTION(WITH_TEST "Option build with test" ON)

# Load build options
INCLUDE(option_build)

# Load jemalloc options
INCLUDE(option_jemalloc)

# Load tls options
INCLUDE(option_tls)

# Load compile flags options
INCLUDE(option_cxxflags)

# Build pump
INCLUDE(build_pump)

# Build pump test
INCLUDE(build_pump_test)

CMAKE_POLICY(POP)
