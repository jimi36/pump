CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

IF(UNIX)
	SET(CMAKE_C_COMPILER gcc)
	SET(CMAKE_CXX_COMPILER g++)
ENDIF()

# Option build with gnutls (default OFF)
OPTION(WITH_GNUTLS "Option build with gnutls" ON)
IF(WITH_GNUTLS)
    ADD_DEFINITIONS("-DUSE_GNUTLS")
ENDIF()

# Option build with jemalloc (default OFF)
OPTION(WITH_JEMALLOC "Option build with jemalloc" OFF)
IF(WITH_JEMALLOC)
    ADD_DEFINITIONS("-DJEMALLOC_MANGLE")
ENDIF()

# Option build with iocp, but ignored on linux (default NO)
OPTION(WITH_IOCP "Option build with iocp, but ignored on linux" OFF)
IF(WIN32 AND WITH_IOCP)
	ADD_DEFINITIONS("-DUSE_IOCP")
ENDIF()

# Option build type debug or release (default Debug)
OPTION(BUILD_DEBUG "Option build type debug or release" ON)
IF(BUILD_DEBUG)
    SET(CMAKE_BUILD_TYPE Debug)
	#SET(CMAKE_DEBUG_POSTFIX "d")
ELSE()
    SET(CMAKE_BUILD_TYPE Release)
endif()
SET(CMAKE_CONFIGURATION_TYPES ${CMAKE_BUILD_TYPE} CACHE STRING "" FORCE)

PROJECT(pump_main)

# Library name
SET(LIBRARY_NAME "pump")

# Project root dir
SET(ROOT_DIR ${PROJECT_SOURCE_DIR})

# Set libraries path
LINK_DIRECTORIES(${ROOT_DIR}/lib)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

# Set include path
INCLUDE_DIRECTORIES(${ROOT_DIR}/include)

# Append cmake module path
LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

INCLUDE(find_libraries)
INCLUDE(set_complie_flags)
INCLUDE(build_pump_library)
INCLUDE(build_test_project)

build_pump_library()

build_test_project("test_transport")

build_test_project("test_simple")

build_test_project("test_timer")
