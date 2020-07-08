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

#ifndef pump_protocol_websocket_frame_h
#define pump_protocol_websocket_frame_h

#include "pump/headers.h"

namespace pump {
	namespace protocol {
		namespace websocket {

			#define FRAME_OPTCODE_SEQUEL 0x0
			#define FRAME_OPTCODE_TEXT   0x1
			#define FRAME_OPTCODE_BINARY 0x2
			#define FRAME_OPTCODE_CLOSE  0x8
			#define FRAME_OPTCODE_PING   0x9
			#define FRAME_OPTCODE_PONG   0xA

			struct frame_header
			{
				uint32 fin : 1;

				uint32 rsv1 : 1;
				uint32 rsv2 : 1;
				uint32 rsv3 : 1;

				uint32 optcode : 4;

				uint32 mask : 1;

				uint32 payload_len : 7;
				uint64 ex_payload_len;

				uint8 mask_key[4];
			};
			DEFINE_RAW_POINTER_TYPE(frame_header);

			/*********************************************************************************
			 * Init frame header
			 ********************************************************************************/
			void init_frame_header(
				frame_header_ptr hdr,
				uint32 fin,
				uint32 optcode,
				uint32 mask,
				uint8 mask_key[4],
				uint64 payload_len
			);

			/*********************************************************************************
			 * Get ws frame header size
			 ********************************************************************************/
			uint32 get_frame_header_size(c_frame_header_ptr hdr);

			/*********************************************************************************
			 * Decode ws frame header
			 ********************************************************************************/
			int32 decode_frame_header(c_block_ptr b, uint32 size, frame_header_ptr hdr);

			/*********************************************************************************
			 * Encode ws frame header
			 ********************************************************************************/
			int32 encode_frame_header(
				c_frame_header_ptr hdr,
				block_ptr b,
				uint32 size
			);

			/*********************************************************************************
			 * Mask transform
			 ********************************************************************************/
			void mask_transform(uint8_ptr b, uint32 size, uint8 mask_key[4]);
		}
	}
}

#endif 
