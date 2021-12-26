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

#ifndef pump_protocol_http_ws_frame_h
#define pump_protocol_http_ws_frame_h

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace http {

    typedef uint32_t ws_frame_optcode_type;
    const ws_frame_optcode_type WS_FOT_SEQUEL = 0x00;
    const ws_frame_optcode_type WS_FOT_TEXT   = 0x01;
    const ws_frame_optcode_type WS_FOT_BINARY = 0x02;
    const ws_frame_optcode_type WS_FOT_CLOSE  = 0x08;
    const ws_frame_optcode_type WS_FOT_PING   = 0x09;
    const ws_frame_optcode_type WS_FOT_PONG   = 0x0A;

    struct ws_frame_header {
        uint32_t fin : 1;

        uint32_t rsv1 : 1;
        uint32_t rsv2 : 1;
        uint32_t rsv3 : 1;

        ws_frame_optcode_type optcode : 4;

        uint32_t mask : 1;

        uint32_t payload_len : 7;
        uint64_t ex_payload_len;

        uint8_t mask_key[4];
    };

    /*********************************************************************************
     * Init websocket frame header
     ********************************************************************************/
    void init_ws_frame_header(
        ws_frame_header *hdr,
        uint32_t fin,
        ws_frame_optcode_type optcode,
        uint32_t mask,
        uint8_t mask_key[4],
        uint64_t payload_len);

    /*********************************************************************************
     * Get websocket frame header size
     ********************************************************************************/
    int32_t get_ws_frame_header_size(const ws_frame_header *hdr);

    /*********************************************************************************
     * Decode websocket frame header
     ********************************************************************************/
    int32_t decode_ws_frame_header(
        const block_t *b,
        int32_t size,
        ws_frame_header *hdr);

    /*********************************************************************************
     * Encode websocket frame header
     ********************************************************************************/
    int32_t encode_ws_frame_header(
        const ws_frame_header *hdr,
        block_t *b, 
        int32_t size);

    /*********************************************************************************
     * Mask transform websocket payload
     ********************************************************************************/
    void mask_transform_ws_payload(
        uint8_t *b, 
        int32_t size, 
        uint8_t mask_key[4]);

}  // namespace websocket
}  // namespace protocol
}  // namespace pump

#endif
