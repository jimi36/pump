#
# Define macros: 
#   USE_GNUTLS 
#
# Export variables:
#	GNUTLS_LIBRARY - gnutls library link path
#

IF(WITH_GNUTLS)
	FIND_LIBRARY(GNUTLS_LIBRARY NAMES gnutls libgnutls libgnutls.dll)
	MESSAGE(STATUS "GNUTls library: ${GNUTLS_LIBRARY}")
	
	SET(pump_WITH_GNUTLS "WITH_GNUTLS")
ELSE()
	SET(pump_WITH_GNUTLS "WITHOUT_GNUTLS")
ENDIF()