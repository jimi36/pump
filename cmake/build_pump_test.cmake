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
	set_compile_flags(${EXE_COMPILE_FLAGS})

	FILE(GLOB_RECURSE SOURCES ${ROOT_DIR}/test/${NAME}/*)

	IF(WIN32)
		SET(LINK_LIBS "ws2_32.lib")
		IF(TLS_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS};${TLS_LIBRARY}")
		ENDIF()
		IF(CRYPTO_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS};${CRYPTO_LIBRARY}")
		ENDIF()
		IF(JEMALLOC_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS};${JEMALLOC_LIBRARY}")
		ENDIF()
	ELSEIF(UNIX)
		SET(LINK_LIBS "pthread")
        IF(TLS_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS} ${TLS_LIBRARY}")
        ENDIF()
		IF(CRYPTO_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS} ${CRYPTO_LIBRARY}")
		ENDIF()
		IF(JEMALLOC_LIBRARY)
			SET(LINK_LIBS "${LINK_LIBS} ${JEMALLOC_LIBRARY}")
		ENDIF()
	ENDIF()
	
	ADD_EXECUTABLE(${NAME} ${SOURCES} ${COM_SOURCES})
	TARGET_LINK_LIBRARIES(${NAME} ${LINK_LIBS} ${SHARED_LIBRARY_NAME})
	
	IF(WIN32)
		SET_TARGET_PROPERTIES(${NAME} PROPERTIES VS_DEBUGGER_ENVIRONMENT "PATH=${ROOT_DIR}/lib;%PATH%")
	ENDIF()
ENDMACRO()

IF(WITH_TEST)
    build_test_project("test_transport")
    build_test_project("test_simple")
    build_test_project("test_timer")
    build_test_project("test_http")
    build_test_project("test_ws")
ENDIF()
