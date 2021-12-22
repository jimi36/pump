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

#ifndef pump_protocol_quic_varint_h
#define pump_protocol_quic_varint_h

#include <string>

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace quic {

    int32_t varint_length(uint64_t val);

    block_t* varint_encode(block_t *b, int32_t blen, uint64_t val);

    const block_t* varint_decode(const block_t *b, int32_t blen, uint64_t &val);

    template <typename T>
    const block_t* varint_decode_ex(const block_t *b, int32_t blen, T &val){
        uint64_t u64 = 0;
        if ((b = varint_decode(b, blen, u64)) == nullptr) {
            return nullptr;
        }
        val = T(u64);
        return b;
    }

}
}
}

#endif
