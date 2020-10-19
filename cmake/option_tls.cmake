#
# Define macros: 
#   WITH_GNUTLS, WITH_OPENSSL, WITHOUT_TLS
#
# Export variables:
#	TLS_LIBRARY - tls library link path
#	CRYPTO_LIBRARY - crypto library link path
#

IF(WITH_TLS STREQUAL "OPENSSL")
	FIND_LIBRARY(OPENSSL_LIBRARY NAMES ssl libssl)
	FIND_LIBRARY(CRYPTO_LIBRARY NAMES crypto libcrypto)
	SET(TLS_LIBRARY "${OPENSSL_LIBRARY}")
	SET(pump_WITH_TLS "WITH_OPENSSL")
	MESSAGE(STATUS "TLS library: ${OPENSSL_LIBRARY} ${CRYPTO_LIBRARY}")
ELSEIF(WITH_TLS STREQUAL "GNUTLS")
	FIND_LIBRARY(GNUTLS_LIBRARY NAMES gnutls libgnutls libgnutls.dll)
	SET(TLS_LIBRARY "${GNUTLS_LIBRARY}")
	SET(pump_WITH_TLS "WITH_GNUTLS")
	MESSAGE(STATUS "TLS library: ${GNUTLS_LIBRARY}")
ELSE()
	SET(pump_WITH_TLS "WITHOUT_TLS")
ENDIF()