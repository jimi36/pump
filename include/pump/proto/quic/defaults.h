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

#ifndef pump_proto_quic_defaults_h
#define pump_proto_quic_defaults_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

    // UDP receive buffer size should be setted.
    const static int32_t UDP_RECEIVE_BUFFER_SIZE = 1024 * 1024 * 2; // 2mb

    // Maximum IPv4 packet size.
    const static int32_t MAX_PACKET_SIZE_IPV4 = 1252;
    // Maximum IPv6 packet size.
    const static int32_t MAX_PACKET_SIZE_IPV6 = 1232;

    // Max connection id length.
    const static int32_t MAX_CONNECTION_ID_LEN = 20;
    // Ddefault connection id length.
    const static int32_t DEF_CONNECTION_ID_LEN = 4;

    // Max ack delay exponent.
    const static int64_t MAX_ACK_DELAY_EXPONENT = 20;
    // Default ack delay exponent with 3.
    const static int64_t DEF_ACK_DELAY_EXPONENT = 3;

    // MAx max ack delay with 16383 milliseconds.
    const static int64_t MAX_MAX_ACK_DELAY = (1 << 14) - 1;
    // Default max ack delay with 25 milliseconds.
    const static int64_t DEF_MAX_ACK_DELAY = 25;

    // Default idle timeout with 30s.
    const static int64_t DEF_IDLE_TIMEOUT = 30000;
    // Default remote idle timeout for accept with 5s.
    const static int64_t DEF_MIN_REMOTE_IDLE_TIMEOUT = 5000;
    // Default idle timeout used before handshake completion with 5s.
    const static int64_t DEF_HANDSHAKE_IDLE_TIMEOUT = 5000;
    // Default timeout for a connection until the crypto handshake succeeds with 10s.
    const static int64_t DEF_HANDSHAKE_TIMEOUT = 10000;

    // ConnectionFlowControlMultiplier determines how much larger the connection flow control windows 
    // needs to be relative to any stream's flow control window.
    // This is the value that Chromium is using.
    const static float32_t CONNECTION_FLOW_CONTROL_MULTIPLIER = 1.5;

    // Default initial stream-level flow control window for receiving.
    const static int64_t DEF_STREAM_RECEIVE_WINDOW_SIZE = 1024 * 512; // 512 kb
    // Default initial stream-level flow control window for receiving.
    const static int64_t DEF_MAX_STREAM_RECEIVE_WINDOW_SIZE = 1024 * 1024 * 6; // 6 mb

    // Default initial connection-level flow control window for receiving.
    const static int64_t DEF_CONNECTION_RECEIVE_WINDOW_SIZE = DEF_STREAM_RECEIVE_WINDOW_SIZE * CONNECTION_FLOW_CONTROL_MULTIPLIER;
    // Default initial connection-level flow control window for receiving.
    const static int64_t DEF_MAX_CONNECTION_RECEIVE_WINDOW_SIZE = 1024 * 1024 * 15; // 15 mb

    // Default max time until sending a packet to keep a connection alive with 20s.
    // It should be shorter than the time that NATs clear their mapping.
    const static int64_t DEF_MAX_KEEP_ALIVE_INTERVAL = 20000;

    // Default min active connection id limit with 2.
    const static int64_t DEF_MIN_ACTIVE_CID_LIMIT = 2;

    // Default time to keeping closed sessions around in order to retransmit the CONNECTION_CLOSE with 5s.
    // After this time all information about the old connection will be deleted.
    const static int64_t DEF_RETIRED_CID_DELETE_TIMEOUT = 5000;

    // Max size of sessions that the server queues for accepting.
    // If the queue is full, new connection attempts will be rejected.
    const static int64_t MAX_ACCEPT_QUEUE_SIZE = 32;

    // Max stream count value that can be sent in MAX_STREAMS frames and as the stream count.
	// in the transport parameters.
    const static int64_t MAX_STREAM_COUNT = int64_t(1) << 60;
    // Default max incoming streams count.
    const static int64_t DEF_MAX_INCOMING_STREAM_COUNT = 100;
    // // Default max incoming unidirectional streams count.
    const static int64_t DEF_MAX_INCOMING_NUI_STREAM_COUNT = 100;

    // Estimated timer granularity.
    // The loss detection timer will not be set to a value smaller than granularity.
    const int64_t TIMER_GRANULARITY = 1; //ms

}
}
}

#endif