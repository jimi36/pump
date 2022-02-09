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

#ifndef pump_proto_quic_errors_h
#define pump_proto_quic_errors_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

/*********************************************************************************
 * Error types
 ********************************************************************************/
typedef uint64_t error_code;
const error_code EC_NO_ERROR = 0x00;
const error_code EC_INTERNAL_ERROR = 0x01;
const error_code EC_CONNECTION_REFUSED = 0x02;
const error_code EC_FLOW_CONTROL_ERROR = 0x03;
const error_code EC_STREAM_LIMIT_ERROR = 0x04;
const error_code EC_STREAM_STATE_ERROR = 0x05;
const error_code EC_FINAL_SIZE_ERROR = 0x06;
const error_code EC_FRAME_ENCODING_ERROR = 0x07;
const error_code EC_TRANSPORT_PARAMETER_ERROR = 0x08;
const error_code EC_CONNECTIONID_LIMIT_ERROR = 0x09;
const error_code EC_proto_VIOLATION = 0x0a;
const error_code EC_INVALID_TOKEN = 0x0b;
const error_code EC_APPLICATION_ERROR = 0x0c;
const error_code EC_CRYTO_BUFFER_EXCEEDED = 0x0d;
const error_code EC_KEY_UPDATE_ERROR = 0x0e;
const error_code EC_AEAD_LIMIT_REACHED = 0x0f;
const error_code EC_NO_VIABLE_PATH = 0x10;

}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif