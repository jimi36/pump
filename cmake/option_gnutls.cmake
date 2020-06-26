#
# Define macros: 
#   USE_GNUTLS 
#
# Export variables:
#	GNUTLS_LIBRARY - gnutls library link path
#

IF(WITH_GNUTLS)
	ADD_DEFINITIONS("-DUSE_GNUTLS")

	FIND_LIBRARY(GNUTLS_LIBRARY NAMES gnutls libgnutls libgnutls.dll)
	MESSAGE(STATUS "GNUTls library: ${GNUTLS_LIBRARY}")

ENDIF()