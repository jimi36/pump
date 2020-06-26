# 
# Export functions:
#	build_test_project(project_name)
#
# Run:
#   build_test_project("test_transport")
#   build_test_project("test_simple")
#   build_test_project("test_timer")
#

MACRO(build_test_project NAME)
	set_complie_flags(${EXE_COMPILE_FLAGS})

	IF(JEMALLOC_LIBRARY)
		FILE(GLOB COM_SOURCES ${ROOT_DIR}/*.cpp)
	ENDIF()
	FILE(GLOB_RECURSE SOURCES ${ROOT_DIR}/test/${NAME}/*)

	IF(WIN32)
		SET(LINK_LIBS "ws2_32.lib")
		IF(GNUTLS_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS};${GNUTLS_LIBRARY}")
		ENDIF()
		IF(JEMALLOC_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS};${JEMALLOC_LIBRARY}")
		ENDIF()
	ELSEIF(UNIX)
		SET(LINK_LIBS "pthread")
        IF(GNUTLS_LIBRARY)
		SET(LINK_LIBS "${LINK_LIBS} ${GNUTLS_LIBRARY}")
        ENDIF()
		IF(JEMALLOC_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS} ${JEMALLOC_LIBRARY}")
		ENDIF()
	ENDIF()
	
	ADD_EXECUTABLE(${NAME} ${SOURCES} ${COM_SOURCES})
	TARGET_LINK_LIBRARIES(${NAME} ${LINK_LIBS} ${LIBRARY_NAME})
	
	IF(WIN32)
		SET_TARGET_PROPERTIES(${NAME} PROPERTIES VS_DEBUGGER_ENVIRONMENT "PATH=${ROOT_DIR}/lib;%PATH%")
	ENDIF()
ENDMACRO()


build_test_project("test_transport")

build_test_project("test_simple")

build_test_project("test_timer")