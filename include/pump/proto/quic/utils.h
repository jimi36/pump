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

#include "pump/toolkit/buffer.h"
#include "pump/proto/quic/cid.h"

namespace pump {
namespace proto {
namespace quic {

    /*********************************************************************************
     * Read string from io buffer
     ********************************************************************************/
    bool read_string_from_iob(toolkit::io_buffer *iob, std::string &s);

    /*********************************************************************************
     * Write string from io buffer
     ********************************************************************************/
    bool write_string_to_iob(const std::string &s, toolkit::io_buffer *iob);

}
}
}

#endif

