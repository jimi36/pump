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

#include <pump/toolkit/buffer.h>

namespace pump {
namespace proto {
namespace http {

const uint8_t wscode_slice = 0x00;
const uint8_t wscode_text = 0x01;
const uint8_t wscode_bin = 0x02;
const uint8_t wscode_close = 0x08;
const uint8_t wscode_ping = 0x09;
const uint8_t wscode_pong = 0x0A;
const uint8_t wscode_end = 0xFF;

class pump_lib frame_header {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    frame_header(
        bool fin = true,
        uint8_t code = wscode_end,
        uint64_t payload_len = 0);
    frame_header(
        bool fin,
        uint8_t code,
        uint64_t payload_len,
        const std::string &key);

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
     * Check unpacked flag
     ********************************************************************************/
    pump_inline bool is_unpacked() const noexcept {
        return is_unpacked_;
    }

    /*********************************************************************************
     * Check frame fin flag
     ********************************************************************************/
    pump_inline bool is_fin() const noexcept {
        return fin_;
    }

    /*********************************************************************************
     * Get frame code
     ********************************************************************************/
    pump_inline uint8_t get_code() const noexcept {
        return code_;
    }

    /*********************************************************************************
     * Get payload length
     ********************************************************************************/
    pump_inline uint64_t get_payload_length() const noexcept {
        return payload_len_;
    }

  private:
    // Fin flag
    bool fin_;
    // Code
    uint8_t code_;
    // Payload length
    uint64_t payload_len_;
    // Mask key
    std::string key_;
    // Unpacked flag
    bool is_unpacked_;
};

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif