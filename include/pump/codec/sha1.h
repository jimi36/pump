/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
		LIB_PUMP void sha1_init(SHA1_CTX *ctx);

		/*********************************************************************************
		 * Update sha1 context
		 ********************************************************************************/
		LIB_PUMP void sha1_update(SHA1_CTX *ctx, c_uint8_ptr data, uint32 len);

		/*********************************************************************************
		 * Final sha1 context
		 ********************************************************************************/
		LIB_PUMP void sha1_final(SHA1_CTX *ctx, uint8 digest[20]);

		/*********************************************************************************
		 * Sha1
		 ********************************************************************************/
		LIB_PUMP void sha1(c_uint8_ptr str, uint32 len, uint8 digest[20]);

	}
}

#endif /* SHA1_H */
