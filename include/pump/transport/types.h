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
const transport_type transport_udp = 0;
const transport_type transport_tcp_acceptor = 1;
const transport_type transport_tcp_dialer = 2;
const transport_type transport_tcp = 3;
const transport_type transport_tls_acceptor = 4;
const transport_type transport_tls_dialer = 5;
const transport_type transport_tls_handshaker = 6;
const transport_type transport_tls = 7;

/*********************************************************************************
 * Transport state
 ********************************************************************************/
typedef int32_t transport_state;
const transport_state state_none = 0;
const transport_state state_starting = 1;
const transport_state state_started = 2;
const transport_state state_stopping = 3;
const transport_state state_stopped = 4;
const transport_state state_disconnecting = 5;
const transport_state state_disconnected = 6;
const transport_state state_timeouting = 7;
const transport_state state_timeouted = 8;
const transport_state state_handshaking = 9;
const transport_state state_finished = 10;
const transport_state state_error = 11;

/*********************************************************************************
 * Transport read mode
 ********************************************************************************/
typedef int32_t read_mode;
const read_mode read_mode_none = 0;
const read_mode read_mode_once = 1;
const read_mode read_mode_loop = 2;

/*********************************************************************************
 * Transport read state
 ********************************************************************************/
typedef int32_t read_state;
const read_state read_none = 0;
const read_state read_pending = 1;
const read_state read_invalid = 2;

/*********************************************************************************
 * Transport error
 ********************************************************************************/
typedef int32_t error_code;
const error_code error_none = 0;
const error_code error_unstart = 1;
const error_code error_invalid = 2;
const error_code error_disable = 3;
const error_code error_again = 4;
const error_code error_fault = 5;

}  // namespace transport
}  // namespace pump

#endif