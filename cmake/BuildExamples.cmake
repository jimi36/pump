#
# The module build examples project.
# 
# On windows, this will build vs project to compile examples.
#

MACRO(build_example NAME)
	set_complie_flags(${EXE_COMPILE_FLAGS})

	FILE(GLOB_RECURSE SOURCES ${ROOT_DIR}/examples/${NAME}/*)
	
	ADD_EXECUTABLE(${NAME} ${SOURCES})

	IF(WIN32)
		SET(LINK_LIBS "ws2_32.lib;${LIBRABBIT_NAME}.lib")
		IF(HAS_GNUTLS)
			SET(LINK_LIBS "${LINK_LIBS};libgnutls.lib")
		ENDIF()
	ELSEIF(UNIX)
		SET(LINK_LIBS "-lpthread -lrabbit")
                IF(HAS_GNUTLS)
                        SET(LINK_LIBS "${LINK_LIBS} libgnutls.a")
                ENDIF()
	ENDIF()
	
	TARGET_LINK_LIBRARIES (${NAME} ${LINK_LIBS})
ENDMACRO()

build_example("test_transport")
build_example("test_simple")
build_example("test_timer")
