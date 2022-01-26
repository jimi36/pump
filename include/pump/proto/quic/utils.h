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

#ifndef pump_proto_quic_utils_h
#define pump_proto_quic_utils_h

#include <string>

#include "pump/proto/quic/cid.h"

namespace pump {
namespace proto {
namespace quic {

    /*********************************************************************************
     * Read string from io buffer
     ********************************************************************************/
    bool read_string_from_iob(io_buffer *iob, std::string &s);

    /*********************************************************************************
     * Write string from io buffer
     ********************************************************************************/
    bool write_string_to_iob(const std::string &s, io_buffer *iob);

    /*********************************************************************************
     * Read int8 from io buffer
     ********************************************************************************/
    bool read_i8_from_iob(io_buffer *iob, uint8_t &val);

    /*********************************************************************************
     * Write int8 from io buffer
     ********************************************************************************/
    bool write_i8_to_iob(uint8_t val, io_buffer *iob);

    /*********************************************************************************
     * Read int16 from io buffer
     ********************************************************************************/
    bool read_i16_from_iob(io_buffer *iob, uint16_t &val);

    /*********************************************************************************
     * Write int16 from io buffer
     ********************************************************************************/
    bool write_i16_to_iob(uint16_t val, io_buffer *iob);

    /*********************************************************************************
     * Read int24 from io buffer
     ********************************************************************************/
    bool read_i24_from_iob(io_buffer *iob, uint32_t &val);

    /*********************************************************************************
     * Write int24 from io buffer
     ********************************************************************************/
    bool write_i24_to_iob(uint32_t val, io_buffer *iob);

    /*********************************************************************************
     * Read int32 from io buffer
     ********************************************************************************/
    bool read_i32_from_iob(io_buffer *iob, uint32_t &val);

    /*********************************************************************************
     * Write int32 from io buffer
     ********************************************************************************/
    bool write_i32_to_iob(uint32_t val, io_buffer *iob);

    /*********************************************************************************
     * Read int64 from io buffer
     ********************************************************************************/
    bool read_i64_from_iob(io_buffer *iob,uint64_t &val);

    /*********************************************************************************
     * Write int64 from io buffer
     ********************************************************************************/
    bool write_i64_to_iob(uint64_t val, io_buffer *iob);

        /*********************************************************************************
     * GEt varint length of value
     ********************************************************************************/
    int32_t varint_length(uint64_t val);

    /*********************************************************************************
     * Varint encode
     ********************************************************************************/
    bool varint_encode(uint64_t val, io_buffer *iob);

    /*********************************************************************************
     * Varint decode
     ********************************************************************************/
    bool varint_decode(io_buffer *iob, uint64_t *val);

    /*********************************************************************************
     * Varint decode ex
     ********************************************************************************/
    template <typename T>
    bool varint_decode_ex(io_buffer *iob, T *val){
        uint64_t u64 = 0;
        if (!varint_decode(iob, &u64)) {
            return false;
        }
        *val = T(u64);
        return true;
    }

}
}
}

#endif

