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

#ifndef pump_proto_http_frame_h
#define pump_proto_http_frame_h

#include "pump/toolkit/buffer.h"

namespace pump {
namespace proto {
namespace http {

const uint8_t ws_opt_slice = 0x00;
const uint8_t ws_opt_text = 0x01;
const uint8_t ws_opt_bin = 0x02;
const uint8_t ws_opt_close = 0x08;
const uint8_t ws_opt_ping = 0x09;
const uint8_t ws_opt_pong = 0x0A;
const uint8_t ws_opt_end = 0xFF;

class pump_lib frame {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    frame(
        bool fin = true,
        uint8_t opt = ws_opt_end,
        uint64_t payload_len = 0);
    frame(
        bool fin,
        uint8_t opt,
        uint64_t payload_len,
        const std::string &payload_mask_key);

    /*********************************************************************************
     * unpack websocket frame header
     ********************************************************************************/
    bool unpack_header(toolkit::io_buffer *iob);

    /*********************************************************************************
     * Pack websocket frame header
     ********************************************************************************/
    bool pack_header(toolkit::io_buffer *iob);

    /*********************************************************************************
     * Mask websocket payload
     ********************************************************************************/
    void mask_payload(char *b);

    /*********************************************************************************
     * Reset
     ********************************************************************************/
    void reset();

    /*********************************************************************************
     * Check websocket frame header unpacked flag
     ********************************************************************************/
    pump_inline bool is_header_unpacked() const {
        return is_header_unpacked_;
    }

    /*********************************************************************************
     * Check websocket frame fin flag
     ********************************************************************************/
    pump_inline bool is_fin() const {
        return fin_;
    }

    /*********************************************************************************
     * Get websocket frame opt
     ********************************************************************************/
    pump_inline uint8_t get_opt() const {
        return opt_;
    }

    /*********************************************************************************
     * Get websocket frame payload length
     ********************************************************************************/
    pump_inline uint64_t get_payload_length() const {
        return payload_len_;
    }

  private:
    // Frame fin flag
    bool fin_;
    // Frame opt code
    uint8_t opt_;
    // Frame payload length
    uint64_t payload_len_;
    // Frame payload mask key
    std::string payload_mask_key_;
    // Frame header unpacked flag
    bool is_header_unpacked_;
};

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif