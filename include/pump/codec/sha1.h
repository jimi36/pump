#ifndef pump_codec_sha1_h
#define pump_codec_sha1_h

#include "pump/deps.h"

namespace pump {
	namespace codec {

		struct SHA1_CTX
		{
			uint32 state[5];
			uint32 count[2];
			uint8 buffer[64];
		};

		//void sha1_transform(uint32 state[5], const uint8 buffer[64]);

		/*********************************************************************************
		 * Init sha1 context
		 ********************************************************************************/
		LIB_EXPORT void sha1_init(SHA1_CTX *ctx);

		/*********************************************************************************
		 * Update sha1 context
		 ********************************************************************************/
		LIB_EXPORT void sha1_update(SHA1_CTX *ctx, c_uint8_ptr data, uint32 len);

		/*********************************************************************************
		 * Final sha1 context
		 ********************************************************************************/
		LIB_EXPORT void sha1_final(SHA1_CTX *ctx, uint8 digest[20]);

		/*********************************************************************************
		 * Sha1
		 ********************************************************************************/
		LIB_EXPORT void sha1(c_uint8_ptr str, uint32 len, uint8 digest[20]);

	}
}

#endif /* SHA1_H */
