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

#ifndef pump_proto_quic_frames_h
#define pump_proto_quic_frames_h

#include <string>
#include <vector>

#include "pump/proto/quic/cid.h"
#include "pump/proto/quic/types.h"
#include "pump/proto/quic/errors.h"

namespace pump {
namespace proto {
namespace quic {

    /*********************************************************************************
     * Frame types
     ********************************************************************************/
    typedef uint8_t frame_type;
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

    /*********************************************************************************
     * Padding frame
     ********************************************************************************/
    struct padding_frame {};

    /*********************************************************************************
     * Get padding frame length
     ********************************************************************************/
    int32_t length_padding_frame(const padding_frame *frame);

    /*********************************************************************************
     * Pack padding frame
     ********************************************************************************/
    bool pack_padding_frame(const padding_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack padding frame
     ********************************************************************************/
    bool unpack_padding_frame(io_buffer *iob, padding_frame *frame);

    /*********************************************************************************
     * Ping frame
     ********************************************************************************/
    struct ping_frame {};

    /*********************************************************************************
     * Get ping frame length
     ********************************************************************************/
    int32_t length_ping_frame(const ping_frame *frame);

    /*********************************************************************************
     * Pack ping frame
     ********************************************************************************/
    bool pack_ping_frame(const ping_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack ping frame
     ********************************************************************************/
    bool unpack_ping_frame(io_buffer *iob, ping_frame *frame);

    /*********************************************************************************
     * Ack range
     ********************************************************************************/
    struct ack_range {
        uint64_t smallest;
        uint64_t largest;
    };

    /*********************************************************************************
     * Ack frame
     ********************************************************************************/
    struct ack_frame {
        uint64_t ack_delay; // microseconds
        int32_t ack_delay_export;
        std::vector<ack_range> ack_ranges;
        uint64_t ect0;
        uint64_t ect1;
        uint64_t ecnce;
    };

    /*********************************************************************************
     * Get ack frame length
     ********************************************************************************/
    int32_t length_ack_frame(const ack_frame *frame);

    /*********************************************************************************
     * Pack ack frame
     ********************************************************************************/
    bool pack_ack_frame(const ack_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack ack frame
     ********************************************************************************/
    bool unpack_ack_frame(io_buffer *iob, ack_frame *frame);

    /*********************************************************************************
     * Rest stream frame
     ********************************************************************************/
    struct reset_stream_frame {
        uint64_t stream_id;
        uint64_t error_code;
        uint64_t final_size;
    };

    /*********************************************************************************
     * Get reset stream frame length
     ********************************************************************************/
    int32_t length_reset_stream_frame(const reset_stream_frame *frame);

    /*********************************************************************************
     * Pack reset frame
     ********************************************************************************/
    bool pack_reset_stream_frame(const reset_stream_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack reset frame
     ********************************************************************************/
    bool unpack_reset_stream_frame(io_buffer *iob, reset_stream_frame *frame);

    /*********************************************************************************
     * Stop sending frame
     ********************************************************************************/
    struct stop_sending_frame {
        uint64_t stream_id;
        uint64_t error_code;
    };

    /*********************************************************************************
     * Get stop sedning frame length
     ********************************************************************************/
    int32_t length_stop_sending_frame(const stop_sending_frame *frame);

    /*********************************************************************************
     * Pack stop sending frame
     ********************************************************************************/
    bool pack_stop_sending_frame(const stop_sending_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack stop sending frame
     ********************************************************************************/
    bool unpack_stop_sending_frame(io_buffer *iob, stop_sending_frame *frame);

    /*********************************************************************************
     * Crypto frame
     ********************************************************************************/
    struct crypto_frame {
        uint64_t offset;
        std::string data;

    };

    /*********************************************************************************
     * Get crypto frame length
     ********************************************************************************/
    int32_t length_crypto_frame(const crypto_frame *frame);

    /*********************************************************************************
     * Pack crypto frame
     ********************************************************************************/
    bool pack_crypto_frame(const crypto_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack crypto frame
     ********************************************************************************/
    bool unpack_crypto_frame(io_buffer *iob, crypto_frame *frame);

    /*********************************************************************************
     * New token frame
     ********************************************************************************/
    struct new_token_frame {
        std::string token;
    };

    /*********************************************************************************
     * Get new token frame length
     ********************************************************************************/
    int32_t length_new_token_frame(const new_token_frame *frame);

    /*********************************************************************************
     * Pack new token frame
     ********************************************************************************/
    bool pack_new_token_frame(const new_token_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack new token frame
     ********************************************************************************/
    bool unpack_new_token_frame(io_buffer *iob, new_token_frame *frame);

    /*********************************************************************************
     * Stream frame
     ********************************************************************************/
    struct stream_frame {
        uint64_t stream_id;
        bool stream_fin;

        uint64_t offset;
        bool has_offset;

        std::string data;
        bool has_data_len;
    };

    /*********************************************************************************
     * Get stream frame length
     ********************************************************************************/
    int32_t length_stream_frame(const stream_frame *frame);

    /*********************************************************************************
     * Pack stream frame
     ********************************************************************************/
    bool pack_stream_frame(const stream_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack stream frame
     ********************************************************************************/
    bool unpack_stream_frame(io_buffer *iob, stream_frame *frame);

    /*********************************************************************************
     * Max data frame
     ********************************************************************************/
    struct max_data_frame {
        uint64_t max;
    };

    /*********************************************************************************
     * Get max data frame length
     ********************************************************************************/
    int32_t length_max_data_frame(const max_data_frame *frame);

    /*********************************************************************************
     * Pack max data frame
     ********************************************************************************/
    bool pack_max_data_frame(const max_data_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack max data frame
     ********************************************************************************/
    bool unpack_max_data_frame(io_buffer *iob, max_data_frame *frame);

    /*********************************************************************************
     * Max stream data frame
     ********************************************************************************/
    struct max_stream_data_frame {
        uint64_t stream_id;
        uint64_t max;
    };

    /*********************************************************************************
     * Get max stream data frame length
     ********************************************************************************/
    int32_t length_max_stream_data_frame(const max_stream_data_frame *frame);

    /*********************************************************************************
     * Pack max stream data frame
     ********************************************************************************/
    bool pack_max_stream_data_frame(const max_stream_data_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack max stream data frame
     ********************************************************************************/
    bool unpack_max_stream_data_frame(io_buffer *iob, max_stream_data_frame *frame);

    /*********************************************************************************
     * Max streams frame
     ********************************************************************************/
    struct max_streams_frame {
        stream_type st;
        uint64_t max;
    };

    /*********************************************************************************
     * Get max streams frame length
     ********************************************************************************/
    int32_t length_max_streams_frame(const max_streams_frame *frame);

    /*********************************************************************************
     * Pack max streams frame
     ********************************************************************************/
    bool pack_max_streams_frame(const max_streams_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack max streams frame
     ********************************************************************************/
    bool unpack_max_streams_frame(io_buffer *iob, max_streams_frame *frame);

    /*********************************************************************************
     * Data blocked frame
     ********************************************************************************/
    struct data_blocked_frame {
        uint64_t max;
    };

    /*********************************************************************************
     * Get data blocked frame length
     ********************************************************************************/
    int32_t length_data_blocked_frame(const data_blocked_frame *frame);

    /*********************************************************************************
     * Pack data blocked frame
     ********************************************************************************/
    bool pack_data_blocked_frame(const data_blocked_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack data blocked frame
     ********************************************************************************/
    bool unpack_data_blocked_frame(io_buffer *iob, data_blocked_frame *frame);

    /*********************************************************************************
     * Stream data blocked frame
     ********************************************************************************/
    struct stream_data_blocked_frame {
        uint64_t stream_id;
        uint64_t max;
    };

    /*********************************************************************************
     * Get stream data blocked frame length
     ********************************************************************************/
    int32_t length_stream_data_blocked_frame(const stream_data_blocked_frame *frame);

    /*********************************************************************************
     * Pack stream data blocked frame
     ********************************************************************************/
    bool pack_stream_data_blocked_frame(const stream_data_blocked_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack stream data blocked frame
     ********************************************************************************/
    bool pack_stream_data_blocked_frame(io_buffer *iob, stream_data_blocked_frame *frame);

    /*********************************************************************************
     * Stream blocked frame
     ********************************************************************************/
    struct streams_blocked_frame {
        stream_type st;
        uint64_t max;
    };

    /*********************************************************************************
     * Get streams blocked frame length
     ********************************************************************************/
    int32_t length_streams_blocked_frame(const streams_blocked_frame *frame);

    /*********************************************************************************
     * Pack stream blocked frame
     ********************************************************************************/
    bool pack_streams_blocked_frame(const streams_blocked_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack stream blocked frame
     ********************************************************************************/
    bool unpack_streams_blocked_frame(io_buffer *iob, streams_blocked_frame *frame);

    /*********************************************************************************
     * New connection id frame
     ********************************************************************************/
    struct new_connection_id_frame {
        uint64_t seq;
        uint64_t retire_prior_to;
        cid id;
        block_t stateless_reset_token[16];
    };

    /*********************************************************************************
     * Get new connection id frame length
     ********************************************************************************/
    int32_t length_new_connection_id_frame(const new_connection_id_frame *frame);

    /*********************************************************************************
     * Pack new connection id frame
     ********************************************************************************/
    bool pack_new_connection_id_frame(const new_connection_id_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack new connection id frame
     ********************************************************************************/
    bool unpack_new_connection_id_frame(io_buffer *iob, new_connection_id_frame *frame);

    /*********************************************************************************
     * Retire connection id frame
     ********************************************************************************/
    struct retire_connection_id_frame {
        uint64_t seq;
    };

    /*********************************************************************************
     * Get retire connection id frame length
     ********************************************************************************/
    int32_t length_retire_connection_id_frame(const retire_connection_id_frame *frame);

    /*********************************************************************************
     * Pack retire connection id frame
     ********************************************************************************/
    bool pack_retire_connection_id_frame(const retire_connection_id_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack retire connection id frame
     ********************************************************************************/
    bool unpack_retire_connection_id_frame(io_buffer *iob, retire_connection_id_frame *frame);

    /*********************************************************************************
     * Path challenge frame
     ********************************************************************************/
    struct path_challenge_frame {
        block_t data[8];
    };

    /*********************************************************************************
     * Get path challenge frame length
     ********************************************************************************/
    int32_t length_path_challenge_frame(const path_challenge_frame *frame);

    /*********************************************************************************
     * Pack path challenge frame
     ********************************************************************************/
    bool pack_path_challenge_frame(const path_challenge_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack path challenge frame
     ********************************************************************************/
    bool unpack_path_challenge_frame(io_buffer *iob, path_challenge_frame *frame);

    /*********************************************************************************
     * Path response frame
     ********************************************************************************/
    struct path_response_frame {
        block_t data[8];
    };

    /*********************************************************************************
     * Get path response frame length
     ********************************************************************************/
    int32_t length_path_response_frame(const path_response_frame *frame);

    /*********************************************************************************
     * Pack path response frame
     ********************************************************************************/
    bool pack_path_response_frame(const path_response_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack path response frame
     ********************************************************************************/
    bool unpack_path_response_frame(io_buffer *iob, path_response_frame *frame);

    /*********************************************************************************
     * Connection close frame
     ********************************************************************************/
    struct connection_close_frame {
        bool is_application_error;
        error_code ec;
        uint64_t frame_type;
        std::string reason;
    };

    /*********************************************************************************
     * Get connection close frame length
     ********************************************************************************/
    int32_t length_connection_close_frame(const connection_close_frame *frame);

    /*********************************************************************************
     * Pack connection close frame
     ********************************************************************************/
    bool pack_connection_close_frame(const connection_close_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack connection close frame
     ********************************************************************************/
    bool unpack_connection_close_frame(io_buffer *iob, connection_close_frame *frame);

    /*********************************************************************************
     * Handshake done frame
     ********************************************************************************/
    struct handshake_done_frame {};

    /*********************************************************************************
     * Get handshake done frame length
     ********************************************************************************/
    int32_t length_handshake_done_frame(const handshake_done_frame *frame);

    /*********************************************************************************
     * Pack handshake done frame
     ********************************************************************************/
    bool pack_handshake_done_frame(const handshake_done_frame *frame, io_buffer *iob);

    /*********************************************************************************
     * Unpack handshake done frame
     ********************************************************************************/
    bool unpack_handshake_done_frame(io_buffer *iob, handshake_done_frame *frame);

}
}
}

#endif
