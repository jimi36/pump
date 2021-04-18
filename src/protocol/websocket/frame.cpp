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

// Import "memset" on linux
#include <string.h>

#include "pump/toolkit/bits.h"
#include "pump/protocol/websocket/frame.h"

namespace pump {
namespace protocol {
namespace websocket {

    void init_frame_header(
        frame_header *hdr,
        uint32_t fin,
        uint32_t optcode,
        uint32_t mask,
        uint8_t mask_key[4],
        uint64_t payload_len) {
        memset(hdr, 0, sizeof(frame_header));

        hdr->fin = fin;

        hdr->optcode = optcode;

        hdr->mask = mask;
        if (mask == 1) {
            memcpy(hdr->mask_key, mask_key, 4);
        }

        if (payload_len < 126) {
            hdr->payload_len = payload_len;
        } else if (payload_len <= 65535) {
            hdr->payload_len = 126;
            hdr->ex_payload_len = (uint32_t)payload_len;
        } else {
            hdr->payload_len = 127;
            hdr->ex_payload_len = payload_len;
        }
    }

    int32_t get_frame_header_size(const frame_header *hdr) {
        int32_t size = 2;

        if (hdr->mask == 1) {
            size += 4;
        }

        if (hdr->payload_len == 126) {
            size += 2;
        } else if (hdr->payload_len == 127) {
            size += 4;
        }

        return size;
    }

    int32_t decode_frame_header(
        const block_t *b, 
        int32_t size, 
        frame_header *hdr) {
        // Init frame header
        memset(hdr, 0, sizeof(frame_header));

        // Init bits reader
        toolkit::bits_reader r((const uint8_t*)b, size);

#define READ_BITS(bits, tmp, val) \
    if (!r.read(bits, &tmp)) {    \
        return 0;                 \
    }                             \
    val = tmp

        uint32_t tmp32 = 0;
        uint64_t tmp64 = 0;
        READ_BITS(1, tmp32, hdr->fin);
        READ_BITS(1, tmp32, hdr->rsv1);
        READ_BITS(1, tmp32, hdr->rsv2);
        READ_BITS(1, tmp32, hdr->rsv3);
        READ_BITS(4, tmp32, hdr->optcode);
        READ_BITS(1, tmp32, hdr->mask);
        READ_BITS(7, tmp32, hdr->payload_len);
        if (hdr->payload_len == 126) {
            READ_BITS(16, tmp32, hdr->ex_payload_len);
        } else if (hdr->payload_len == 127) {
            READ_BITS(64, tmp64, hdr->ex_payload_len);
        }

#undef READ_BITS

        if (hdr->mask == 1) {
            if (!r.read(8, &hdr->mask_key[0]) ||
                !r.read(8, &hdr->mask_key[1]) ||
                !r.read(8, &hdr->mask_key[2]) ||
                !r.read(8, &hdr->mask_key[3])) {
                return 0;
            }
        }

        return int32_t(r.used_bc() / 8);
    }

    int32_t encode_frame_header(
        const frame_header *hdr, 
        block_t *b, 
        int32_t size) {
        // Init bits writer
        toolkit::bits_writer w((uint8_t*)b, size);

        if (!w.write(1, hdr->fin) ||
            !w.write(1, hdr->rsv1) || 
            !w.write(1, hdr->rsv2) ||
            !w.write(1, hdr->rsv3) ||
            !w.write(4, hdr->optcode) ||
            !w.write(1, hdr->mask) ||
            !w.write(7, hdr->payload_len)) {
            return 0;
        }

        if (hdr->payload_len == 126) {
            if (!w.write(16, hdr->ex_payload_len)) {
                return 0;
            }
        } else if (hdr->payload_len == 127) {
            if (!w.write(64, hdr->ex_payload_len)) {
                return 0;
            }
        }

        if (hdr->mask == 1) {
            if (!w.write(8, hdr->mask_key[0]) || 
                !w.write(8, hdr->mask_key[1]) ||
                !w.write(8, hdr->mask_key[2]) || 
                !w.write(8, hdr->mask_key[3])) {
                return 0;
            }
        }

        return w.used_bc() / 8;
    }

    void mask_transform(
        uint8_t *b, 
        int32_t size, 
        uint8_t mask_key[4]) {
        for (int32_t i = 0; i < size; i++) {
            b[i] = b[i] ^ mask_key[i % 4];
        }
    }

}  // namespace websocket
}  // namespace protocol
}  // namespace pump