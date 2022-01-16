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

#include "pump/utils.h"
#include "pump/proto/http/frame.h"

namespace pump {
namespace proto {
namespace http {

    frame::frame(
        bool fin, 
        uint8_t opt,
        uint64_t payload_len) 
      : fin_(fin), 
        opt_(opt), 
        payload_len_(payload_len),
        is_header_unpacked_(false) {
    }

    frame::frame(
        bool fin, 
        uint8_t opt, 
        uint64_t payload_len, 
        const std::string &payload_mask_key)
      : fin_(fin), 
        opt_(opt), 
        payload_len_(payload_len), 
        payload_mask_key_(payload_mask_key),
        is_header_unpacked_(false) {
    }

    bool frame::unpack_header(toolkit::io_buffer *iob) {
        bool ret = false;
        int32_t read_size = 0;

        do {
            uint8_t b = 0;
            if (!iob->read((block_t*)&b)) {
                break;
            }
            read_size += 1;

            // Unpack fin flag.
            fin_ = (b & 0x80) > 0;

            // Unpack opt code.
            opt_ = b & 0x0f;

            if (!iob->read((block_t*)&b)) {
                break;
            }
            read_size += 1;

            // Unpack payload length.
            payload_len_ = b & 0x0f;
            if (payload_len_ == 126) {
                uint16_t l = 0;
                if (!iob->read((block_t*)&l, sizeof(l))) {
                    break;
                }
                payload_len_ = transform_endian_i16(l);
                read_size += 2;
            } else if (payload_len_ == 127) {
                uint64_t l = 0;
                if (!iob->read((block_t*)&l, sizeof(l))) {
                    break;
                }
                payload_len_ = transform_endian_i64(l);
                read_size += 4;
            }

            // Unpack payload mask key.
            if ((b & 0x80) > 0) {
                payload_mask_key_.resize(4);
                if (!iob->read((block_t*)payload_mask_key_.data(), 4)) {
                    break;
                }
                read_size += 4;
            }

            is_header_unpacked_ = true;

            ret = true;

        } while(false);


        if (!ret) {
            iob->shift(-read_size);
        }

        return ret;
    }

    bool frame::pack_header(toolkit::io_buffer *iob) {
        uint8_t b = opt_;
        if (fin_) {
            b |= 0x80;
        }
        if (!iob->write(b)) {
            return false;
        }

        b = 0;
        if (payload_mask_key_.size() == 4) {
            b = 0x80;
        }
        if (payload_len_ < 126) {
            b |= uint8_t(payload_len_);
        } else if (payload_len_ <= 65535) {
            b |= 126;
        } else {
            b |= 127;
        }
        if (!iob->write(b)) {
            return false;
        }

        if (payload_len_ >= 126 && payload_len_ <= 65535) {
            uint16_t l = transform_endian_i16(payload_len_);
            if (!iob->write((block_t*)&l, sizeof(l))) {
                return false;
            }
        } else if (payload_len_ > 65535) {
            uint64_t l = transform_endian_i64(payload_len_);
            if (!iob->write((block_t*)&l, sizeof(l))) {
                return false;
            }
        }

        if (payload_mask_key_.size() == 4) {
            if (!iob->write(payload_mask_key_.data(), 4)) {
                return false;
            }
        }

        return true;
    }

    void frame::mask_payload(uint8_t *b) {
        if (payload_mask_key_.size() == 4) {
            for (uint64_t i = 0; i < payload_len_; i++) {
                b[i] = b[i] ^ payload_mask_key_[i % 4];
            }
        }
    }

    void frame::reset() {
        fin_ = true;
        opt_ = WS_OPT_END;
        payload_len_ = 0;
        payload_mask_key_.clear();
    }

}
}
}