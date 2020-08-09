#
# Export variables:
#	LIB_COMPILE_FLAGS - compile lib flags
#	EXE_COMPILE_FLAGS - compile exe flags
# 
# Export functions:
#	set_compile_flags(flags)
#

IF(WIN32)
	IF(BUILD_DEBUG)
		SET(LIB_COMPILE_FLAGS "/W3 /ZI /Od /MDd")
		SET(EXE_COMPILE_FLAGS "/W3 /ZI /Od /MDd")
	ELSE()
		SET(LIB_COMPILE_FLAGS "/W3 /O2 /MD")
		SET(EXE_COMPILE_FLAGS "/W3 /O2 /MD")
	ENDIF()
ELSEIF(UNIX)
	IF (BUILD_DEBUG)
		SET(LIB_COMPILE_FLAGS "-std=c++11 -g -O0 -Wall -fPIC -shared")
		SET(EXE_COMPILE_FLAGS "-std=c++11 -g -O0 -Wall")
	ELSE()
		SET(LIB_COMPILE_FLAGS "-std=c++11 -O2 -Wall -fPIC -shared")
		SET(EXE_COMPILE_FLAGS "-std=c++11 -O2 -Wall")
	ENDIF()
ENDIF()


MACRO(set_compile_flags FLAGS)
	IF(WIN32)
		IF(BUILD_DEBUG)
			SET(CMAKE_CXX_FLAGS_DEBUG ${FLAGS})
		ELSE()
			SET(CMAKE_CXX_FLAGS_RELEASE ${FLAGS})
		ENDIF()
	ELSEIF(UNIX)
		IF(BUILD_DEBUG)
			SET(CMAKE_CXX_FLAGS ${FLAGS})
		ELSE()
			SET(CMAKE_CXX_FLAGS ${FLAGS})
		ENDIF()
	ENDIF()
ENDMACRO()
