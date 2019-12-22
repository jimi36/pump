#
# The module set compiler.
# 
# On windows, vs2017 project will be created, so the compiler
# should not be confged.
#
# On linux, the compiler should be configed.
#

IF(UNIX)
	SET(CMAKE_C_COMPILER gcc)
	SET(CMAKE_CXX_COMPILER g++)
ENDIF()
