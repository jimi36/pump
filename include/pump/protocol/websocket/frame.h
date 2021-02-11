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

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace websocket {

    const uint32_t FRAME_OPTCODE_SEQUEL = 0x0;
    const uint32_t FRAME_OPTCODE_TEXT = 0x1;
    const uint32_t FRAME_OPTCODE_BINARY = 0x2;
    const uint32_t FRAME_OPTCODE_CLOSE = 0x8;
    const uint32_t FRAME_OPTCODE_PING = 0x9;
    const uint32_t FRAME_OPTCODE_PONG = 0xA;

    struct frame_header {
        uint32_t fin : 1;

        uint32_t rsv1 : 1;
        uint32_t rsv2 : 1;
        uint32_t rsv3 : 1;

        uint32_t optcode : 4;

        uint32_t mask : 1;

        uint32_t payload_len : 7;
        uint64_t ex_payload_len;

        uint8_t mask_key[4];
    };
    DEFINE_RAW_POINTER_TYPE(frame_header);

    /*********************************************************************************
     * Init frame header
     ********************************************************************************/
    void init_frame_header(frame_header_ptr hdr,
                           uint32_t fin,
                           uint32_t optcode,
                           uint32_t mask,
                           uint8_t mask_key[4],
                           uint64_t payload_len);

    /*********************************************************************************
     * Get ws frame header size
     ********************************************************************************/
    int32_t get_frame_header_size(c_frame_header_ptr hdr);

    /*********************************************************************************
     * Decode ws frame header
     ********************************************************************************/
    int32_t decode_frame_header(const block_t *b, int32_t size, frame_header_ptr hdr);

    /*********************************************************************************
     * Encode ws frame header
     ********************************************************************************/
    int32_t encode_frame_header(c_frame_header_ptr hdr, block_t *b, int32_t size);

    /*********************************************************************************
     * Mask transform
     ********************************************************************************/
    void mask_transform(uint8_t *b, int32_t size, uint8_t mask_key[4]);

}  // namespace websocket
}  // namespace protocol
}  // namespace pump

#endif
