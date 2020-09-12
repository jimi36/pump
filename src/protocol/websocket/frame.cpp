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

        void init_frame_header(frame_header_ptr hdr,
                               uint32 fin,
                               uint32 optcode,
                               uint32 mask,
                               uint8 mask_key[4],
                               uint64 payload_len) {
            memset(hdr, 0, sizeof(frame_header));

            hdr->fin = fin;

            hdr->optcode = optcode;

            hdr->mask = mask;
            if (mask == 1)
                memcpy(hdr->mask_key, mask_key, 4);

            if (payload_len < 126) {
                hdr->payload_len = payload_len;
            } else if (payload_len <= 65535) {
                hdr->payload_len = 126;
                hdr->ex_payload_len = (uint32)payload_len;
            } else {
                hdr->payload_len = 127;
                hdr->ex_payload_len = payload_len;
            }
        }

        uint32 get_frame_header_size(c_frame_header_ptr hdr) {
            uint32 size = 2;

            if (hdr->mask == 1)
                size += 4;

            if (hdr->payload_len == 126)
                size += 2;
            else if (hdr->payload_len == 127)
                size += 4;

            return size;
        }

        int32 decode_frame_header(c_block_ptr b, uint32 size, frame_header_ptr hdr) {
            uint32 tmp32 = 0;
            uint64 tmp64 = 0;

            memset(hdr, 0, sizeof(frame_header));

            toolkit::bits_reader r((c_uint8_ptr)b, size);

            if (!r.read(1, &tmp32))
                return 0;
            hdr->fin = tmp32;

            if (!r.read(1, &tmp32))
                return 0;
            hdr->rsv1 = tmp32;
            if (!r.read(1, &tmp32))
                return 0;
            hdr->rsv2 = tmp32;
            if (!r.read(1, &tmp32))
                return 0;
            hdr->rsv3 = tmp32;

            if (!r.read(4, &tmp32))
                return 0;
            hdr->optcode = tmp32;

            if (!r.read(1, &tmp32))
                return 0;
            hdr->mask = tmp32;

            if (!r.read(7, &tmp32))
                return 0;
            hdr->payload_len = tmp32;
            if (hdr->payload_len == 126) {
                if (!r.read(16, &tmp32))
                    return 0;
                hdr->ex_payload_len = tmp32;
            } else if (hdr->payload_len == 127) {
                if (!r.read(64, &tmp64))
                    return 0;
                hdr->ex_payload_len = tmp64;
            }

            if (hdr->mask == 1) {
                if (!r.read(8, &hdr->mask_key[0]))
                    return 0;
                if (!r.read(8, &hdr->mask_key[1]))
                    return 0;
                if (!r.read(8, &hdr->mask_key[2]))
                    return 0;
                if (!r.read(8, &hdr->mask_key[3]))
                    return 0;
            }

            return r.used_bc() / 8;
        }

        int32 encode_frame_header(c_frame_header_ptr hdr, block_ptr b, uint32 size) {
            toolkit::bits_writer w((uint8_ptr)b, size);

            if (!w.write(1, hdr->fin))
                return 0;

            if (!w.write(1, hdr->rsv1))
                return 0;
            if (!w.write(1, hdr->rsv2))
                return 0;
            if (!w.write(1, hdr->rsv3))
                return 0;

            if (!w.write(4, hdr->optcode))
                return 0;

            if (!w.write(1, hdr->mask))
                return 0;

            if (!w.write(7, hdr->payload_len))
                return 0;

            if (hdr->payload_len == 126) {
                if (!w.write(16, hdr->ex_payload_len))
                    return 0;
            } else if (hdr->payload_len == 127) {
                if (!w.write(64, hdr->ex_payload_len))
                    return 0;
            }

            if (hdr->mask == 1) {
                if (!w.write(8, hdr->mask_key[0]))
                    return 0;
                if (!w.write(8, hdr->mask_key[1]))
                    return 0;
                if (!w.write(8, hdr->mask_key[2]))
                    return 0;
                if (!w.write(8, hdr->mask_key[3]))
                    return 0;
            }

            return w.used_bc() / 8;
        }

        void mask_transform(uint8_ptr b, uint32 size, uint8 mask_key[4]) {
            for (uint32 i = 0; i < size; i++) {
                b[i] = b[i] ^ mask_key[i % 4];
            }
        }

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump