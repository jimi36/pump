CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(pump_main)

# Specifies library name
SET(LIBRARY_NAME "pump")

SET(pump_MAJOR_VERSION 1)
SET(pump_MINOR_VERSION 2)
SET(pump_BUILD_VERSION 9)

# Specifies root dir
SET(ROOT_DIR ${PROJECT_SOURCE_DIR})

# Append cmake module path
LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Option build type debug or release (default Debug)
OPTION(BUILD_DEBUG "Option build type debug or release" OFF)
INCLUDE(option_build)

# Option build with iocp, but ignored on linux (default OFF)
OPTION(WITH_IOCP "Option build with iocp, but ignored on linux" ON)
INCLUDE(option_iocp)

# Option build with jemalloc (default OFF)
OPTION(WITH_JEMALLOC "Option build with jemalloc" OFF)
INCLUDE(option_jemalloc)

# Option build with gnutls (default OFF)
OPTION(WITH_GNUTLS "Option build with gnutls" OFF)
INCLUDE(option_gnutls)

# Load set_compile_flags
INCLUDE(set_compile_flags)

# Build pump library
INCLUDE(build_pump_library)

# Build test project 
INCLUDE(build_test_project)
