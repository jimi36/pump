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
#include "pump/proto/quic/varint.h"

namespace pump {
namespace proto {
namespace quic {

    const uint64_t MAX_VARINT_1 = uint64_t(1) << 6;  // 64
    const uint64_t MAX_VARINT_2 = uint64_t(1) << 14; // 16384
    const uint64_t MAX_VARINT_4 = uint64_t(1) << 30; // 1073741824
    const uint64_t MAX_VARINT_8 = uint64_t(1) << 62; // 4611686018427387904

    int32_t varint_length(uint64_t val) {
        if (val < MAX_VARINT_1) {
            return 1;
        } else if (val < MAX_VARINT_2) {
            return 2;
        } else if (val < MAX_VARINT_4) {
            return 4;
        } else if (val < MAX_VARINT_8) {
            return 8;
        }
        return -1;
    }

    bool varint_encode(uint64_t val, toolkit::io_buffer *iob) {
        if (val < MAX_VARINT_1) {
            return iob->write(block_t(val));
        } else if (val < MAX_VARINT_2) {
            block_t b[2];
            b[0] = block_t(val >> 8) | 0x40;
            b[1] = block_t(val);
            return iob->write(b, 2);
        } else if (val < MAX_VARINT_4) {
            block_t b[4];
            b[0] = block_t(val >> 24) | 0x80;
            b[1] = block_t(val >> 16);
            b[2] = block_t(val >> 8);
            b[3] = block_t(val);
            return iob->write(b, 4);
        } else if (val < MAX_VARINT_8) {
            block_t b[8];
            b[0] = block_t(val >> 56) | 0xc0;
            b[1] = block_t(val >> 48);
            b[2] = block_t(val >> 40);
            b[3] = block_t(val >> 32);
            b[4] = block_t(val >> 24);
            b[5] = block_t(val >> 16);
            b[6] = block_t(val >> 8);
            b[7] = block_t(val);
            return iob->write(b, 8);
        }
        return false;
    }

    bool varint_decode(toolkit::io_buffer *iob, uint64_t *val) {
        uint8_t b[8];
        if (!iob->read((block_t*)b)) {
            return false;
        }

        int32_t len = 1 << ((b[0] & 0xc0) >> 6);
        if (len == 1) {
            *val = uint64_t(b[0] & 0x3f);
        } else if (len == 2) {
            if (!iob->read((block_t*)(b + 1))) {
                return false;
            }
            *val = (uint64_t(b[0] & 0x3f) << 8) + uint64_t(b[1]);
        } else if (len == 4) {
            if (!iob->read((block_t*)b + 1, 3)) {
                return false;
            }
            *val = (uint64_t(b[0] & 0x3f) << 24) + 
                  (uint64_t(b[1]) << 16) + 
                  (uint64_t(b[2]) << 8) + 
                  (uint64_t(b[3]));
        } else if (len == 8) {
            if (!iob->read((block_t*)b + 1, 7)) {
                return false;
            }
            *val = (uint64_t(b[0] & 0x3f) << 56) + 
                  (uint64_t(b[1]) << 48) + 
                  (uint64_t(b[2]) << 40) + 
                  (uint64_t(b[3]) << 32) +
                  (uint64_t(b[4]) << 24) + 
                  (uint64_t(b[5]) << 16) +
                  (uint64_t(b[6]) << 8) +
                  (uint64_t(b[7]));
        }

        return true;
    }

}
}
}