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

    // The acknowledgment delay exponent is an integer value indicating an exponent used to decode 
    // the ACK Delay field in the ACK frame. If this value is absent, a default value of 3 is assumed
    // (indicating a multiplier of 8). Values above 20 are invalid.
    const int32_t ACK_DELAY_EXPONENT = 3;

	typedef uint64_t error_code;
	const error_code EC_NO_ERROR                  = 0x00;
	const error_code EC_INTERNAL_ERROR            = 0x01;
	const error_code EC_CONNECTION_REFUSED        = 0x02;
	const error_code EC_FLOW_CONTROL_ERROR        = 0x03;
	const error_code EC_STREAM_LIMIT_ERROR        = 0x04;
	const error_code EC_STREAM_STATE_ERROR        = 0x05;
	const error_code EC_FINAL_SIZE_ERROR          = 0x06;
	const error_code EC_FRAME_ENCODING_ERROR      = 0x07;
	const error_code EC_TRANSPORT_PARAMETER_ERROR = 0x08;
	const error_code EC_CONNECTIONID_LIMIT_ERROR  = 0x09;
	const error_code EC_PROTOCOL_VIOLATION        = 0x0a;
	const error_code EC_INVALID_TOKEN             = 0x0b;
	const error_code EC_APPLICATION_ERROR         = 0x0c;
	const error_code EC_CRYTO_BUFFER_EXCEEDED     = 0x0d;
	const error_code EC_KEY_UPDATE_ERROR          = 0x0e;
	const error_code EC_AEAD_LIMIT_REACHED        = 0x0f;
	const error_code EC_NO_VIABLE_PATH            = 0x10;

    typedef block_t frame_type;
    const frame_type FT_PADDING              = 0x00;
    const frame_type FT_PING                 = 0x01;
    const frame_type FT_ACK                  = 0x02;
    const frame_type FT_ACK_ECN              = 0x03;
    const frame_type FT_RESET_STREAM         = 0x04;
    const frame_type FT_STOP_SENDING         = 0x05;
    const frame_type FT_CRYPTO               = 0x06;
    const frame_type FT_NEW_TOKEN            = 0x07;
    const frame_type FT_STREAM               = 0x08;
    const frame_type FT_MAX_DATA             = 0x10;
    const frame_type FT_MAX_STREAM_DATA      = 0x11;
    const frame_type FT_MAX_BIDISTREAMS      = 0x12;
    const frame_type FT_MAX_UNISTREAMS       = 0x13;
    const frame_type FT_DATA_BLOCKED         = 0x14;
    const frame_type FT_STREAM_DATA_BLOCKED  = 0x15;
    const frame_type FT_BIDISTREAMS_BLOCKED  = 0x16;
    const frame_type FT_UNISTREAMS_BLOCKED   = 0x17;
    const frame_type FT_NEW_CONNECTION_ID    = 0x18;
    const frame_type FT_RETIRE_CONNECTION_ID = 0x19;
    const frame_type FT_PATH_CHALLENGE       = 0x1a;
    const frame_type FT_PATH_RESPONSE        = 0x1b;
    const frame_type FT_Q_CONNECTION_CLOSE   = 0x1c; // quic layer close connection
    const frame_type FT_A_CONNECTION_CLOSE   = 0x1d; // application layer close conection
    const frame_type FT_HANDSHAKE_DONE       = 0x1e;   

    typedef block_t stream_type;
    const stream_type stream_bidirection  = 0x00;
    const stream_type stream_unidirection = 0x02;

}
}
}

#endif