#
# Export variables:
#	LIB_COMPILE_FLAGS - compile lib flags
#	EXE_COMPILE_FLAGS - compile exe flags
# 
# Export functions:
#	set_complie_flags(flags)
#

IF(WIN32)
	IF(BUILD_DEBUG)
		SET(LIB_COMPILE_FLAGS "/W3 /ZI /O2 /MDd")
		SET(EXE_COMPILE_FLAGS "/W3 /ZI /O2 /MDd")
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


MACRO(set_complie_flags FLAGS)
	IF(BUILD_DEBUG)
		SET(CMAKE_CXX_FLAGS ${FLAGS})
	ELSE()
		SET(CMAKE_CXX_FLAGS ${FLAGS})
	ENDIF()
ENDMACRO()
