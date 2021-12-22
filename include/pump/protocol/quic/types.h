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

#ifndef pump_protocol_quic_types_h
#define pump_protocol_quic_types_h

#include <string>
#include <vector>

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace quic {

    typedef int8_t stream_type;
    const stream_type stream_bidirection  = 0x00;
    const stream_type stream_unidirection = 0x02;

}
}
}

#endif