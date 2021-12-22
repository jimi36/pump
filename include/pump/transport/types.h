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

#ifndef pump_transport_types_h
#define pump_transport_types_h

#include "pump/types.h"

namespace pump {
namespace transport {

    /*********************************************************************************
     * Transport type
     ********************************************************************************/
    typedef int32_t transport_type;
    const transport_type UDP_TRANSPORT  = 0;
    const transport_type TCP_ACCEPTOR   = 1;
    const transport_type TCP_DIALER     = 2;
    const transport_type TCP_TRANSPORT  = 3;
    const transport_type TLS_ACCEPTOR   = 4;
    const transport_type TLS_DIALER     = 5;
    const transport_type TLS_HANDSHAKER = 6;
    const transport_type TLS_TRANSPORT  = 7;

    /*********************************************************************************
     * Transport state
     ********************************************************************************/
    typedef int32_t transport_state;
    const transport_state TRANSPORT_INITED        = 0;
    const transport_state TRANSPORT_STARTING      = 1;
    const transport_state TRANSPORT_STARTED       = 2;
    const transport_state TRANSPORT_STOPPING      = 3;
    const transport_state TRANSPORT_STOPPED       = 4;
    const transport_state TRANSPORT_DISCONNECTING = 5;
    const transport_state TRANSPORT_DISCONNECTED  = 6;
    const transport_state TRANSPORT_TIMEOUTING    = 7;
    const transport_state TRANSPORT_TIMEOUTED     = 8;
    const transport_state TRANSPORT_HANDSHAKING   = 9;
    const transport_state TRANSPORT_FINISHED      = 10;
    const transport_state TRANSPORT_ERROR         = 11;

    /*********************************************************************************
     * Transport read mode
     ********************************************************************************/
    typedef int32_t read_mode;
    const read_mode READ_MODE_NONE = 0;
    const read_mode READ_MODE_ONCE = 1;
    const read_mode READ_MODE_LOOP = 2;

    /*********************************************************************************
     * Transport read state
     ********************************************************************************/
    typedef int32_t read_state;
    const read_state READ_NONE    = 0;
    const read_state READ_PENDING = 1;
    const read_state READ_INVALID = 2;

    /*********************************************************************************
     * Transport error
     ********************************************************************************/
    typedef int32_t error_code;
    const error_code ERROR_OK      = 0;
    const error_code ERROR_UNSTART = 1;
    const error_code ERROR_INVALID = 2;
    const error_code ERROR_DISABLE = 3;
    const error_code ERROR_AGAIN   = 4;
    const error_code ERROR_FAULT   = 5;

}  // namespace transport
}  // namespace pump

#endif