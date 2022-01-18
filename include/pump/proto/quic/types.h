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

#ifndef pump_proto_quic_types_h
#define pump_proto_quic_types_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

    typedef uint32_t version_number;
    const static version_number version_1       = 0x01;
    const static version_number version_draft29 = 0xff00001d;
    const static version_number version_max     = 0xffffffff;

    /*********************************************************************************
     * Stream initiator types
     ********************************************************************************/
    typedef int8_t stream_initiator_type;
    const static stream_initiator_type server_initiator = 0x01;
    const static stream_initiator_type client_initiator = 0x02;   

    /*********************************************************************************
     * Stream types
     ********************************************************************************/
    typedef int8_t stream_type;
    const static stream_type stream_bidirection  = 0x00;
    const static stream_type stream_unidirection = 0x02;

}
}
}

#endif