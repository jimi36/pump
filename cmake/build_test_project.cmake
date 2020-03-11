# 
# Export functions:
#	build_test_project(project_name)
#

MACRO(build_test_project NAME)
	set_complie_flags(${EXE_COMPILE_FLAGS})

	FILE(GLOB_RECURSE SOURCES ${ROOT_DIR}/test/${NAME}/*)

	IF(WIN32)
		SET(LINK_LIBS "ws2_32.lib;${OUTPUT_TARGET_LIB}.lib")
		IF(WITH_GNUTLS)
			SET(LINK_LIBS "${LINK_LIBS};libgnutls.lib")
		ENDIF()
	ELSEIF(UNIX)
		SET(LINK_LIBS "pthread ${OUTPUT_TARGET_LIB}")
        IF(WITH_GNUTLS)
            SET(LINK_LIBS "${LINK_LIBS} gnutls")
        ENDIF()
	ENDIF()
	
	ADD_EXECUTABLE(${NAME} ${SOURCES})
	TARGET_LINK_LIBRARIES (${NAME} ${LINK_LIBS})
ENDMACRO()
