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

//#include "pump/debug.h"
//#include "pump/codec/base64.h"
#include "pump/utils.h"
#include "pump/protocol/quic/packets.h"

namespace pump {
namespace protocol {
namespace quic {

    int32_t pack_packet_header(const long_packet_header *hdr, block_t *b, int32_t blen) {
        int32_t idx = 0;

        *(b + idx) = block_t(0xc0 | hdr->tp << 4);
        if (hdr->tp != LPT_NEGOTIATION && hdr->tp != LPT_RETRY) {
            *(b + idx) |= block_t(hdr->packet_number_len - 1);
        }
        idx += 1;

        *(uint32_t*)(b + idx) = transform_endian(hdr->version);
        idx += 4;

        *(b + idx) = (block_t)hdr->des_id.length();
        idx += 1;

        memcpy(b + idx, hdr->des_id.data(), hdr->des_id.length());
        idx += hdr->des_id.length();

        *(b + idx) = (block_t)hdr->src_id.length();
        idx += 1;

        memcpy(b + idx, hdr->src_id.data(), hdr->src_id.length());
        idx += hdr->src_id.length();

        return idx;
    }

    int32_t unpack_packet_header(const block_t *b, int32_t blen, long_packet_header *hdr) {
        return 0;
    }

}
}
}