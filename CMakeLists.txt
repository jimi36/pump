CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(librabbit_mian)

# Option build debug type (default Debug)
OPTION(BUILD_DEBUG "Set build type to Debug or Release (default Debug)" ON)
IF(BUILD_DEBUG)
    SET(CMAKE_BUILD_TYPE Debug)
ELSE()
    SET(CMAKE_BUILD_TYPE Release)
endif()

# Option gnutls (default Yes)
OPTION(HAS_GNUTLS "Set has gnutls yes or no (default yes)" OFF)
IF(HAS_GNUTLS)
    ADD_DEFINITIONS("-DUSE_GNUTLS")
ENDIF()

# Option iocp (default no)
OPTION(HAS_IOCP "Set has iocp yes or no (default no)" OFF)
IF(WIN32 AND HAS_IOCP)
	ADD_DEFINITIONS("-DUSE_IOCP")
ENDIF()

# Define root dir
SET(ROOT_DIR ${PROJECT_SOURCE_DIR})

# Define librabbit name
SET(LIBRABBIT_NAME "librabbit")

LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

INCLUDE(SetCompiler)

INCLUDE(SetCompileFlags)

INCLUDE(SetCompilePaths)

INCLUDE(BuildLibrabbit)

INCLUDE(BuildExamples)
