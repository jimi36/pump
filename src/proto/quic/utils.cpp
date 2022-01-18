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
#include "pump/proto/quic/utils.h"

namespace pump {
namespace proto {
namespace quic {

    bool read_string_from_iob(toolkit::io_buffer *iob, std::string &s) {
        if (s.size() == 0) {
            return false;
        } else if (!iob->read((block_t*)s.data(), s.size())) {
            return false;
        }
        return true;
    }

    bool write_string_to_iob(const std::string &s, toolkit::io_buffer *iob) {
        if (s.size() == 0) {
            return false;
        } else if (!iob->write(s.data(), s.size())) {
            return false;
        }
        return true;
    }

    bool read_i8_from_iob(io_buffer *iob, uint8_t &val) {
        if (!iob->read((block_t*)&val)) {
            return false;
        }
        return true;
    }

    bool write_i8_to_iob(uint8_t val, io_buffer *iob) {
        if (!iob->write(val)) {
            return false;
        }
        return true;
    }

    bool read_i16_from_iob(io_buffer *iob, uint16_t &val) {
        if (!iob->read((block_t*)&val, 2)) {
            return false;
        }
        val = transform_endian_i16(val);
        return true;
    }

    bool write_i16_to_iob(uint16_t val, io_buffer *iob) {
        uint16_t i = transform_endian_i16(val);
        if (!iob->write((block_t*)&i, 2)) {
            return false;
        }
        return true;
    }

    bool read_i24_from_iob(io_buffer *iob, uint32_t &val) {
        if (!iob->read((block_t*)&val + 1, 3)) {
            return false;
        }
        val = transform_endian_i32(val);
        return true;
    }

    bool write_i24_to_iob(uint32_t val, io_buffer *iob) {
        uint32_t i = transform_endian_i32(val);
        if (!iob->write((block_t*)&i + 1, 3)) {
            return false;
        }
        return true;
    }

    bool read_i32_from_iob(io_buffer *iob, uint32_t &val) {
        if (!iob->read((block_t*)&val, 4)) {
            return false;
        }
        val = transform_endian_i32(val);
        return true;
    }

    bool write_i32_to_iob(uint32_t val, io_buffer *iob) {
        uint32_t i = transform_endian_i32(val);
        if (!iob->write((block_t*)&i, 4)) {
            return false;
        }
        return true;
    }

    bool read_i64_from_iob(io_buffer *iob, uint64_t &val) {
        if (!iob->read((block_t*)&val, 8)) {
            return false;
        }
        val = transform_endian_i64(val);
        return true;
    }

    bool write_i64_to_iob(uint64_t val, io_buffer *iob) {
        uint64_t i = transform_endian_i64(val);
        if (!iob->write((block_t*)&i, 8)) {
            return false;
        }
        return true;
    }

}
}
}