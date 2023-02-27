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

frame_header::frame_header(
    bool fin,
    uint8_t code,
    uint64_t payload_len)
  : fin_(fin),
    code_(code),
    payload_len_(payload_len),
    is_unpacked_(false) {
}

frame_header::frame_header(
    bool fin,
    uint8_t code,
    uint64_t payload_len,
    const std::string &key)
  : fin_(fin),
    code_(code),
    payload_len_(payload_len),
    key_(key),
    is_unpacked_(false) {
}

bool frame_header::unpack_header(toolkit::io_buffer *iob) {
    auto iob_size = iob->size();
    do {
        char b = 0;
        if (!iob->read(&b)) {
            break;
        }

        fin_ = (b & 0x80) > 0;
        code_ = (b & 0x0f);

        if (!iob->read(&b)) {
            break;
        }

        payload_len_ = b & 0x0f;
        if (payload_len_ == 126) {
            uint16_t l = 0;
            if (!iob->read((char *)&l, sizeof(l))) {
                break;
            }
            payload_len_ = transform_endian_i16(l);
        } else if (payload_len_ == 127) {
            uint64_t l = 0;
            if (!iob->read((char *)&l, sizeof(l))) {
                break;
            }
            payload_len_ = transform_endian_i64(l);
        }

        if ((b & 0x80) > 0) {
            key_.resize(4);
            if (!iob->read((char *)key_.data(), 4)) {
                break;
            }
        }

        // Unpack header finished
        is_unpacked_ = true;
    } while (false);

    if (!is_unpacked_) {
        iob->shift(iob->size() - iob_size);
    }

    return is_unpacked_;
}

bool frame_header::pack_header(toolkit::io_buffer *iob) {
    auto b = code_;
    if (fin_) {
        b |= 0x80;
    }
    if (!iob->write(b, 1)) {
        return false;
    }

    b = 0;
    if (key_.size() == 4) {
        b = 0x80;
    }
    if (payload_len_ < 126) {
        b |= uint8_t(payload_len_);
    } else if (payload_len_ <= 65535) {
        b |= 126;
    } else {
        b |= 127;
    }
    if (!iob->write((char)b, 1)) {
        return false;
    }

    if (payload_len_ >= 126 && payload_len_ <= 65535) {
        auto l = transform_endian_i16(payload_len_);
        if (!iob->write((char *)&l, sizeof(l))) {
            return false;
        }
    } else if (payload_len_ > 65535) {
        auto l = transform_endian_i64(payload_len_);
        if (!iob->write((char *)&l, sizeof(l))) {
            return false;
        }
    }

    if (key_.size() == 4) {
        if (!iob->write(key_.data(), 4)) {
            return false;
        }
    }

    return true;
}

void frame_header::mask_payload(char *b) {
    if (key_.size() == 4) {
        for (uint64_t i = 0; i < payload_len_; i++) {
            b[i] = b[i] ^ key_[i % 4];
        }
    }
}

void frame_header::reset() {
    fin_ = true;
    code_ = wscode_end;
    payload_len_ = 0;
    key_.clear();
}

}  // namespace http
}  // namespace proto
}  // namespace pump