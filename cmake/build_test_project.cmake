# 
# Export functions:
#	build_test_project(project_name)
#

MACRO(build_test_project NAME)
	set_complie_flags(${EXE_COMPILE_FLAGS})

	FILE(GLOB_RECURSE SOURCES ${ROOT_DIR}/test/${NAME}/*)
	
	ADD_EXECUTABLE(${NAME} ${SOURCES})

	IF(WIN32)
		SET(LINK_LIBS "ws2_32.lib;${LIBRARY_NAME}.lib")
		IF(WITH_GNUTLS)
			SET(LINK_LIBS "${LINK_LIBS};libgnutls.lib")
		ENDIF()
	ELSEIF(UNIX)
		SET(LINK_LIBS "-lpthread -l${LIBRARY_NAME}")
        IF(WITH_GNUTLS)
            SET(LINK_LIBS "${LINK_LIBS} libgnutls.a")
        ENDIF()
	ENDIF()
	
	TARGET_LINK_LIBRARIES (${NAME} ${LINK_LIBS})
ENDMACRO()
