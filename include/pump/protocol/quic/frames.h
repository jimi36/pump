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

#ifndef pump_protocol_quic_frames_h
#define pump_protocol_quic_frames_h

#include <string>
#include <vector>

#include "pump/protocol/quic/cid.h"
#include "pump/protocol/quic/types.h"
#include "pump/protocol/quic/errors.h"

namespace pump {
namespace protocol {
namespace quic {

    typedef int8_t frame_type;
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

    struct padding_frame {};

    int32_t encode_padding_frame(const padding_frame *frame, block_t *b, int32_t blen);

    int32_t decode_padding_frame(const block_t *b, int32_t blen, padding_frame *frame);

    int32_t length_padding_frame(const padding_frame *frame);

    struct ping_frame {};

    int32_t encode_ping_frame(const ping_frame *frame, block_t *b, int32_t blen);

    int32_t decode_ping_frame(const block_t *b, int32_t blen, ping_frame *frame);

    int32_t length_ping_frame(const ping_frame *frame);

    struct ack_range {
        uint64_t smallest;
        uint64_t largest;
    };

    struct ack_frame {
        uint64_t ack_delay; // microseconds
        int32_t ack_delay_export;
        std::vector<ack_range> ack_ranges;
        uint64_t ect0;
        uint64_t ect1;
        uint64_t ecnce;
    };

    int32_t encode_ack_frame(const ack_frame *frame, block_t *b, int32_t blen);

    int32_t decode_ack_frame(const block_t *b, int32_t blen, ack_frame *frame);

    int32_t length_ack_frame(const ack_frame *frame);

    struct reset_stream_frame {
        uint64_t stream_id;
        uint64_t error_code;
        uint64_t final_size;
    };

    int32_t encode_reset_stream_frame(const reset_stream_frame *frame, block_t *b, int32_t blen);

    int32_t decode_reset_stream_frame(const block_t *b, int32_t blen, reset_stream_frame *frame);

    int32_t length_reset_stream_frame(const reset_stream_frame *frame);

    struct stop_sending_frame {
        uint64_t stream_id;
        uint64_t error_code;
    };

    int32_t encode_stop_sending_frame(const stop_sending_frame *frame, block_t *b, int32_t blen);

    int32_t decode_stop_sending_frame(const block_t *b, int32_t blen, stop_sending_frame *frame);

    int32_t length_stop_sending_frame(const stop_sending_frame *frame);

    struct crypto_frame {
        uint64_t offset;
        std::string data;

    };

    int32_t encode_crypto_frame(const crypto_frame *frame, block_t *b, int32_t blen);

    int32_t decode_crypto_frame(const block_t *b, int32_t blen, crypto_frame *frame);

    int32_t length_crypto_frame(const crypto_frame *frame);

    struct new_token_frame {
        std::string token;
    };

    int32_t encode_new_token_frame(const new_token_frame *frame, block_t *b, int32_t blen);

    int32_t decode_new_token_frame(const block_t *b, int32_t blen, new_token_frame *frame);

    int32_t length_new_token_frame(const new_token_frame *frame);

    struct stream_frame {
        uint64_t stream_id;
        bool stream_fin;

        uint64_t offset;
        bool has_offset;

        std::string data;
        bool has_data_len;
    };

    int32_t encode_stream_frame(const stream_frame *frame, block_t *b, int32_t blen);

    int32_t decode_stream_frame(const block_t *b, int32_t blen, stream_frame *frame);

    int32_t length_stream_frame(const stream_frame *frame);

    struct max_data_frame {
        uint64_t max;
    };

    int32_t encode_max_data_frame(const max_data_frame *frame, block_t *b, int32_t blen);

    int32_t decode_max_data_frame(const block_t *b, int32_t blen, max_data_frame *frame);

    int32_t length_max_data_frame(const max_data_frame *frame);

    struct max_stream_data_frame {
        uint64_t stream_id;
        uint64_t max;
    };

    int32_t encode_max_stream_data_frame(const max_stream_data_frame *frame, block_t *b, int32_t blen);

    int32_t decode_max_stream_data_frame(const block_t *b, int32_t blen, max_stream_data_frame *frame);

    int32_t length_max_stream_data_frame(const max_stream_data_frame *frame);

    struct max_streams_frame {
        stream_type st;
        uint64_t max;
    };

    int32_t encode_max_streams_frame(const max_streams_frame *frame, block_t *b, int32_t blen);

    int32_t decode_max_streams_frame(const block_t *b, int32_t blen, max_streams_frame *frame);

    int32_t length_max_streams_frame(const max_streams_frame *frame);

    struct data_blocked_frame {
        uint64_t max;
    };

    int32_t encode_data_blocked_frame(const data_blocked_frame *frame, block_t *b, int32_t blen);

    int32_t decode_data_blocked_frame(const block_t *b, int32_t blen, data_blocked_frame *frame);

    int32_t length_data_blocked_frame(const data_blocked_frame *frame);

    struct stream_data_blocked_frame {
        uint64_t stream_id;
        uint64_t max;
    };

    int32_t encode_stream_data_blocked_frame(const stream_data_blocked_frame *frame, block_t *b, int32_t blen);

    int32_t decode_stream_data_blocked_frame(const block_t *b, int32_t blen, stream_data_blocked_frame *frame);

    int32_t length_stream_data_blocked_frame(const stream_data_blocked_frame *frame);

    struct streams_blocked_frame {
        stream_type st;
        uint64_t max;
    };

    int32_t encode_streams_blocked_frame(const streams_blocked_frame *frame, block_t *b, int32_t blen);

    int32_t decode_streams_blocked_frame(const block_t *b, int32_t blen, streams_blocked_frame *frame);

    int32_t length_streams_blocked_frame(const streams_blocked_frame *frame);

    struct new_connection_id_frame {
        uint64_t seq;
        uint64_t retire_prior_to;
        cid id;
        block_t stateless_reset_token[16];
    };

    int32_t encode_new_connection_id_frame(const new_connection_id_frame *frame, block_t *b, int32_t blen);

    int32_t decode_new_connection_id_frame(const block_t *b, int32_t blen, new_connection_id_frame *frame);

    int32_t length_new_connection_id_frame(const new_connection_id_frame *frame);

    struct retire_connection_id_frame {
        uint64_t seq;
    };

    int32_t encode_retire_connection_id_frame(const retire_connection_id_frame *frame, block_t *b, int32_t blen);

    int32_t decode_retire_connection_id_frame(const block_t *b, int32_t blen, retire_connection_id_frame *frame);

    int32_t length_retire_connection_id_frame(const retire_connection_id_frame *frame);

    struct path_challenge_frame {
        block_t data[8];
    };

    int32_t encode_path_challenge_frame(const path_challenge_frame *frame, block_t *b, int32_t blen);

    int32_t decode_path_challenge_frame(const block_t *b, int32_t blen, path_challenge_frame *frame);

    int32_t length_path_challenge_frame(const path_challenge_frame *frame);

    struct path_response_frame {
        block_t data[8];
    };

    int32_t encode_path_response_frame(const path_response_frame *frame, block_t *b, int32_t blen);

    int32_t decode_path_response_frame(const block_t *b, int32_t blen, path_response_frame *frame);

    int32_t length_path_response_frame(const path_response_frame *frame);

    struct connection_close_frame {
        bool is_application_error;
        error_code ec;
        uint64_t frame_type;
        std::string reason;
    };

    int32_t encode_connection_close_frame(const connection_close_frame *frame, block_t *b, int32_t blen);

    int32_t decode_connection_close_frame(const block_t *b, int32_t blen, connection_close_frame *frame);

    int32_t length_connection_close_frame(const connection_close_frame *frame);

    struct handshake_done_frame {
    };

    int32_t encode_handshake_done_frame(const handshake_done_frame *frame, block_t *b, int32_t blen);

    int32_t decode_handshake_done_frame(const block_t *b, int32_t blen, handshake_done_frame *frame);

    int32_t length_handshake_done_frame(const handshake_done_frame *frame);

}
}
}

#endif
