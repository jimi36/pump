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

#include "pump/types.h"
#include "pump/protocol/quic/types.h"
#include "pump/protocol/quic/connection_id.h"

namespace pump {
namespace protocol {
namespace quic {

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
        connection_id id;
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
