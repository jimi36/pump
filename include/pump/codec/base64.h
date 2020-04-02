#ifndef pump_codec_base64_h
#define pump_codec_base64_h

#include "pump/deps.h"

namespace pump {
	namespace codec {

		/*********************************************************************************
		 * Base64 encode
		 ********************************************************************************/
		LIB_EXPORT bool base64_encode(const std::string &in, std::string &out);

		/*********************************************************************************
		 * Base64 decode
		 ********************************************************************************/
		LIB_EXPORT bool base64_decode(const std::string &in, std::string &out);

	}
}

#endif
