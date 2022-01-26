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

#include "pump/debug.h"
#include "pump/proto/quic/utils.h"
#include "pump/proto/quic/frames.h"
#include "pump/proto/quic/defaults.h"

namespace pump {
namespace proto {
namespace quic {

    int32_t length_padding_frame(const padding_frame *frame) {
        return 1;
    }

    bool pack_padding_frame(const padding_frame *frame, io_buffer *iob) {
        return iob->write(FT_PADDING);
    }

    bool unpack_padding_frame(io_buffer *iob, padding_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_PADDING) {
            return false;
        }
        return true;
    }

    int32_t length_ping_frame(const ping_frame *frame) {
        return 1;
    }

    bool pack_ping_frame(const ping_frame *frame, io_buffer *iob) {
        return iob->write(FT_PING);
    }

    bool unpack_ping_frame(io_buffer *iob, ping_frame *frame){
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_PING) {
            return false;
        }
        return true;
    }

    static uint64_t __encode_ack_delay(uint64_t ack_delay, int32_t ack_delay_export) {
        if (ack_delay_export <= 0) {
            ack_delay_export = DEF_ACK_DELAY_EXPONENT;
        }
        return ack_delay / (1 << ack_delay_export);
    }

    static uint64_t __decode_ack_delay(uint64_t delay, int32_t ack_delay_export) {
        if (ack_delay_export <= 0) {
            ack_delay_export = DEF_ACK_DELAY_EXPONENT;
        }
        return delay * (1 << ack_delay_export);
    }

    static uint32_t __ack_range_count(const ack_frame *frame) {
        int32_t max_ack_frame_len = 1000;
        max_ack_frame_len -= varint_length(frame->ack_ranges[0].largest); // reduce length of largest_ack.
        max_ack_frame_len -= varint_length(__encode_ack_delay(frame->ack_delay, frame->ack_delay_export)); // reduce length of ack_delay.
        max_ack_frame_len -= 2; // reduce length of ack range count(maybe 2 bytes).
        max_ack_frame_len -= 2; // reduce length of first ack range(maybe 2 bytes).
        for (uint32_t i = 1; i < (uint32_t)frame->ack_ranges.size(); i++) {
            uint64_t gap = frame->ack_ranges[i - 1].smallest - frame->ack_ranges[i].largest - 2;
            uint64_t len = frame->ack_ranges[i].largest - frame->ack_ranges[i].smallest;
            max_ack_frame_len -= (varint_length(gap) + varint_length(len));
            if (max_ack_frame_len <= 0) {
                return i - 1;
            }
        }
        return uint32_t(frame->ack_ranges.size() - 1);
    }

    int32_t length_ack_frame(const ack_frame *frame) {
        uint32_t range_count = __ack_range_count(frame);
        uint64_t first_range = frame->ack_ranges[0].largest - frame->ack_ranges[0].smallest;
        uint64_t ack_delay = __encode_ack_delay(frame->ack_delay, frame->ack_delay_export);

        int64_t frame_len = 1;
        frame_len += varint_length(frame->ack_ranges[0].largest);
        frame_len += varint_length(ack_delay);
        frame_len += varint_length(range_count);
        frame_len += varint_length(first_range);

        for (uint32_t i = 1; i <= range_count; i++) {
            uint64_t gap = frame->ack_ranges[i - 1].smallest - frame->ack_ranges[i].largest - 2;
            uint64_t len = frame->ack_ranges[i].largest - frame->ack_ranges[i].smallest;
            frame_len += varint_length(gap);
            frame_len += varint_length(len);
        }

        if (frame->ect0 > 0 || frame->ect1 > 0 || frame->ecnce > 0) {
            frame_len += varint_length(frame->ect0);
            frame_len += varint_length(frame->ect1);
            frame_len += varint_length(frame->ecnce);
        }

        return (int32_t)frame_len;
    }

    bool pack_ack_frame(const ack_frame *frame, io_buffer *iob) {
        frame_type tp = FT_ACK;
        if (frame->ect0 > 0 || frame->ect1 > 0 || frame->ecnce > 0) {
            tp = FT_ACK_ECN;
        }
        if (!iob->write(tp)) {
            return false;
        }

        uint32_t range_count = __ack_range_count(frame);
        uint64_t first_range = frame->ack_ranges[0].largest - frame->ack_ranges[0].smallest;
        uint64_t ack_delay = __encode_ack_delay(frame->ack_delay, frame->ack_delay_export);
        if (!varint_encode(frame->ack_ranges[0].largest, iob) || 
            !varint_encode(ack_delay, iob) ||
            !varint_encode(range_count, iob) ||
            !varint_encode(first_range, iob)) {
            return false;
        }

        for (uint32_t i = 1; i <= range_count; i++) {
            uint64_t gap = frame->ack_ranges[i - 1].smallest - frame->ack_ranges[i].largest - 2;
            uint64_t len = frame->ack_ranges[i].largest - frame->ack_ranges[i].smallest;
            if (!varint_encode(gap, iob) || 
                !varint_encode(len, iob)) {
                return false;
            }
        }

        if (tp == FT_ACK_ECN) {
            if (!varint_encode(frame->ect0, iob) || 
                !varint_encode(frame->ect1, iob) ||
                !varint_encode(frame->ecnce, iob)) {
                return false;
            }
        }

        return true;
    }

    bool unpack_ack_frame(io_buffer *iob, ack_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_ACK && tp != FT_ACK_ECN) {
            return false;
        }

        uint64_t largest_ack = 0;
        if (!varint_decode(iob, &largest_ack)) {
            return false;
        }

        uint64_t delay = 0;
        if (!varint_decode(iob, &delay)) {
            return false;
        }
        frame->ack_delay = __decode_ack_delay(delay, frame->ack_delay_export);

        uint64_t range_count = 0;
        if (!varint_decode(iob, &range_count)) {
            return false;
        }

        uint64_t first_range = 0;
        if (!varint_decode(iob, &first_range) || first_range > largest_ack) {
            return false;
        }
        uint64_t smallest = largest_ack - first_range;
        frame->ack_ranges.push_back(ack_range{smallest, largest_ack});

        for (uint64_t i = 0; i < range_count; i++) {
            uint64_t gap , len;
            if (!varint_decode(iob, &gap) ||
                !varint_decode(iob, &len)) {
                return false;
            }
            
            uint64_t largest = smallest - gap - 2;
            if (len > largest) {
                return false;
            }

            smallest = largest - len;
            frame->ack_ranges.push_back(ack_range{smallest, largest});
        }

        if (tp == FT_ACK_ECN) {
            if (!varint_decode(iob, &frame->ect0) ||
                !varint_decode(iob, &frame->ect1) ||
                !varint_decode(iob, &frame->ecnce)) {
                return false;
            }
        }

        return true;
    }

    int32_t length_reset_stream_frame(const reset_stream_frame *frame) {
        int32_t len = 1;
        len += varint_length(frame->stream_id);
        len += varint_length(frame->error_code);
        len += varint_length(frame->final_size);
        return len;
    }

    bool pack_reset_stream_frame(const reset_stream_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_RESET_STREAM)) {
            return false;
        }

        if (!varint_encode(frame->stream_id, iob) ||
            !varint_encode(frame->error_code, iob) ||
            !varint_encode(frame->final_size, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_reset_stream_frame(io_buffer *iob, reset_stream_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_RESET_STREAM) {
            return false;
        }

        if (!varint_decode(iob, &frame->stream_id) || 
            !varint_decode(iob, &frame->error_code) || 
            !varint_decode(iob, &frame->final_size)) {
            return false;
        }

        return true;
    }

    int32_t length_stop_sending_frame(const stop_sending_frame *frame){
        int32_t len = 1;
        len += varint_length(frame->stream_id);
        len += varint_length(frame->error_code);
        return len;
    }

    bool pack_stop_sending_frame(const stop_sending_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_STOP_SENDING)) {
            return false;
        }

        if (!varint_encode(frame->stream_id, iob) ||
            !varint_encode(frame->error_code, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_stop_sending_frame(io_buffer *iob, stop_sending_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_STOP_SENDING) {
            return false;
        }

        if (!varint_decode(iob, &frame->stream_id) ||
            !varint_decode(iob, &frame->error_code)) {
            return false;
        }

        return true;
    }

    int32_t length_crypto_frame(const crypto_frame *frame) {
        int32_t len = 1;
        len += varint_length(frame->offset);
        len += varint_length(frame->data.size());
        len += (int32_t)frame->data.size();
        return len;
    }

    bool pack_crypto_frame(const crypto_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_CRYPTO)) {
            return false;
        }

        if (!varint_encode(frame->offset, iob) ||
            !varint_encode(frame->data.size(), iob)) {
            return false;
        }
        if (!iob->write(frame->data.data(), frame->data.size())) {
            return false;
        }

        return true;
    }

    bool unpack_crypto_frame(io_buffer *iob, crypto_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_CRYPTO) {
            return false;
        }

        if (!varint_decode(iob, &frame->offset)) {
            return false;
        }

        uint64_t len = 0;
        if (!varint_decode(iob, &len)) {
            return false;
        }
        frame->data.resize(len);
        if (!read_string_from_iob(iob, frame->data)) {
            return false;
        }

        return true;
    }

    int32_t length_new_token_frame(const new_token_frame *frame) {
        int32_t len = 1;
        len += varint_length(frame->token.size());
        len += (int32_t)frame->token.size();
        return len;
    }

    bool pack_new_token_frame(const new_token_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_NEW_TOKEN)) {
            return false;
        }

        if (!varint_encode(frame->token.size(), iob)) {
            return false;
        }
        if (!iob->write(frame->token.data(), frame->token.size())) {
            return false;
        }

        return true;
    }

    bool unpack_new_token_frame(io_buffer *iob, new_token_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_NEW_TOKEN) {
            return false;
        }

        uint64_t len = 0;
        if (!varint_decode(iob, &len)) {
            return false;
        }
        frame->token.resize(len);
        if (!read_string_from_iob(iob, frame->token)) {
            return false;
        }

        return true;
    }

    int32_t length_stream_frame(const stream_frame *frame) {
        int32_t len = 1;
        len += varint_length(frame->stream_id);
        if (frame->has_offset) {
            len += varint_length(frame->offset);
        }
        if (frame->has_data_len) {
            len += varint_length(frame->data.size());
        }
        len += (int32_t)frame->data.size();
        return len;
    }

    bool pack_stream_frame(const stream_frame *frame, io_buffer *iob) {
        block_t tp = FT_STREAM;
        if (frame->stream_fin) {
            tp |= 0x01;
        }
        if (frame->has_data_len) {
            tp |= 0x02;
        }
        if (frame->has_offset) {
            tp |= 0x04;
        }
        if (!iob->write(tp)) {
            return false;
        }

        if (!varint_encode(frame->stream_id, iob)) {
            return false;
        }

        if (frame->has_offset && !varint_encode(frame->offset, iob)) {
            return false;
        }

        if (frame->has_data_len && !varint_encode(frame->data.size(), iob)) {
            return false;
        }
        if (!iob->write(frame->data.data(), frame->data.size())) {
            return false;
        }

        return true;
    }

    bool unpack_stream_frame(io_buffer *iob, stream_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp < FT_STREAM) {
            return false;
        }

        if (!varint_decode(iob, &frame->stream_id)) {
            return false;
        }

        frame->stream_fin = false;
        if (tp && 0x01) {
            frame->stream_fin = true;
        }

        if (tp & 0x02 && !varint_decode(iob, &frame->offset)) {
            return false;
        }

        uint64_t len = iob->size();
        if (tp & 0x04 && !varint_decode(iob, &len)) {
            return false;
        }
        frame->data.resize(len);
        if (!read_string_from_iob(iob, frame->data)) {
            return false;
        }

        return true;
    }

    int32_t length_max_data_frame(const max_data_frame *frame) {
        return 1 + varint_length(frame->max);
    }

    bool pack_max_data_frame(const max_data_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_MAX_DATA)) {
            return false;
        }

        if (!varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_max_data_frame(io_buffer *iob, max_data_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_MAX_DATA) {
            return false;
        }

        if (!varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_max_stream_data_frame(const max_stream_data_frame *frame) {
        return 1 + varint_length(frame->stream_id) + varint_length(frame->max);
    }

    bool pack_max_stream_data_frame(const max_stream_data_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_MAX_STREAM_DATA)) {
            return false;
        }

        if (!varint_encode(frame->stream_id, iob) ||
            !varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_max_stream_data_frame(io_buffer *iob, max_stream_data_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_MAX_STREAM_DATA) {
            return false;
        }

        if (!varint_decode(iob, &frame->stream_id) ||
            !varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_max_streams_frame(const max_streams_frame *frame) {
        return 1 + varint_length(frame->max);
    }

    bool pack_max_streams_frame(const max_streams_frame *frame, io_buffer *iob) {
        frame_type tp = FT_MAX_UNISTREAMS;
        if (frame->st == stream_bidirection) {
            tp = FT_MAX_BIDISTREAMS;
        }
        if (!iob->write(tp)) {
            return false;
        }
        
        if (!varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_max_streams_frame(io_buffer *iob, max_streams_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        }
        if (tp == FT_MAX_BIDISTREAMS) {
            frame->st = stream_bidirection;
        } else if (tp == FT_MAX_UNISTREAMS) {
            frame->st = stream_unidirection;
        } else {
            return false;
        }

        if (!varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_data_blocked_frame(const data_blocked_frame *frame) {
        return 1 + varint_length(frame->max);
    }

    bool pack_data_blocked_frame(const data_blocked_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_DATA_BLOCKED)) {
            return false;
        }

        if (!varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_data_blocked_frame(io_buffer *iob, data_blocked_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_DATA_BLOCKED) {
            return false;
        }

        if (!varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_stream_data_blocked_frame(const stream_data_blocked_frame *frame) {
        return 1 + varint_length(frame->stream_id) + varint_length(frame->max);
    }

    bool pack_stream_data_blocked_frame(const stream_data_blocked_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_STREAM_DATA_BLOCKED)) {
            return false;
        }

        if (!varint_encode(frame->stream_id, iob) ||
            !varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_stream_data_blocked_frame(io_buffer *iob, stream_data_blocked_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_STREAM_DATA_BLOCKED) {
            return false;
        }

        if (!varint_decode(iob, &frame->stream_id) ||
            !varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_streams_blocked_frame(const streams_blocked_frame *frame) {
        return 1 + varint_length(frame->max);
    }

    bool pack_streams_blocked_frame(const streams_blocked_frame *frame, io_buffer *iob) {
        frame_type tp = FT_UNISTREAMS_BLOCKED;
        if (frame->st == stream_bidirection) {
            tp = FT_BIDISTREAMS_BLOCKED;
        }
        if (!iob->write(tp)) {
            return false;
        }

        if (!varint_encode(frame->max, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_streams_blocked_frame(io_buffer *iob, streams_blocked_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        }
        if (tp == FT_BIDISTREAMS_BLOCKED) {
            frame->st = stream_bidirection;
        } else if (tp == FT_UNISTREAMS_BLOCKED) {
            frame->st = stream_unidirection;
        } else {
            return false;
        }

        if (!varint_decode(iob, &frame->max)) {
            return false;
        }

        return true;
    }

    int32_t length_new_connection_id_frame(const new_connection_id_frame *frame) {
        int32_t len = 1;
        len += varint_length(frame->seq);
        len += varint_length(frame->retire_prior_to);
        len += varint_length(frame->id.length()) + frame->id.length();
        len += sizeof(frame->stateless_reset_token);
        return len;
    }

    bool pack_new_connection_id_frame(const new_connection_id_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_NEW_CONNECTION_ID)) {
            return false;
        }

        if (!varint_encode(frame->seq, iob) ||
            !varint_encode(frame->retire_prior_to, iob)) {
            return false;
        }

        if (!varint_encode(frame->id.length(), iob)) {
            return false;
        }
        if (!iob->write(frame->id.data(), frame->id.length())) {
            return false;
        }

        if (!iob->write(frame->stateless_reset_token, sizeof(frame->stateless_reset_token))) {
            return false;
        }

        return true;
    }

    bool unpack_new_connection_id_frame(io_buffer *iob, new_connection_id_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_NEW_CONNECTION_ID) {
            return false;
        }

        if (!varint_decode(iob, &frame->seq) ||
            !varint_decode(iob, &frame->retire_prior_to)) {
            return false;
        }

        uint64_t id_len = 0;
        if (!varint_decode(iob, &id_len)) {
            return false;
        }
        if (!frame->id.read_from(iob, id_len)) {
            return false;
        }

        if (!iob->read(frame->stateless_reset_token, sizeof(frame->stateless_reset_token))) {
            return false;
        }

        return true;
    }

    int32_t length_retire_connection_id_frame(const retire_connection_id_frame *frame) {
        return 1 + varint_length(frame->seq);
    }

    bool pack_retire_connection_id_frame(const retire_connection_id_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_RETIRE_CONNECTION_ID)) {
            return false;
        }

        if (!varint_encode(frame->seq, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_retire_connection_id_frame(io_buffer *iob, retire_connection_id_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_RETIRE_CONNECTION_ID) {
            return false;
        }

        if (!varint_decode(iob, &frame->seq)) {
            return false;
        }

        return true;
    }

    int32_t length_path_challenge_frame(const path_challenge_frame *frame) {
        return 1 + sizeof(frame->data);
    }

    bool pack_path_challenge_frame(const path_challenge_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_PATH_CHALLENGE)) {
            return false;
        }

        if (!iob->write(frame->data, sizeof(frame->data))) {
            return false;
        }

        return true;
    }

    bool unpack_path_challenge_frame(io_buffer *iob, path_challenge_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_PATH_CHALLENGE) {
            return false;
        }

        if (!iob->read(frame->data, sizeof(frame->data))) {
            return false;
        }

        return true;
    }

    int32_t length_path_response_frame(const path_response_frame *frame) {
        return 1 + sizeof(frame->data);
    }

    bool pack_path_response_frame(const path_response_frame *frame, io_buffer *iob) {
        if (!iob->write(FT_PATH_RESPONSE)) {
            return false;
        }

        if (!iob->write(frame->data, sizeof(frame->data))) {
            return false;
        }

        return true;
    }

    bool unpack_path_response_frame(io_buffer *iob, path_response_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        } else if (tp != FT_PATH_RESPONSE) {
            return false;
        }

        if (!iob->read(frame->data, sizeof(frame->data))) {
            return false;
        }
        
        return true;
    }

    int32_t length_connection_close_frame(const connection_close_frame *frame) {
        return 1 + varint_length(frame->ec) + varint_length(frame->reason.size()) + frame->reason.size();
    }

    bool pack_connection_close_frame(const connection_close_frame *frame, io_buffer *iob){
        frame_type tp = FT_Q_CONNECTION_CLOSE;
        if (frame->is_application_error) {
            tp = FT_A_CONNECTION_CLOSE;
        }
        if (!iob->write(tp)) {
            return false;
        }
        
        if (!varint_encode(frame->ec, iob)) {
            return false;
        }

        if (!varint_encode(frame->reason.size(), iob)) {
            return false;
        }
        if (!iob->write(frame->reason.data(), frame->reason.size())) {
            return false;
        }

        return true;
    }

    bool unpack_connection_close_frame(io_buffer *iob, connection_close_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        }
        if (tp == FT_Q_CONNECTION_CLOSE) {
            frame->is_application_error = false;
        } else if (tp == FT_A_CONNECTION_CLOSE) {
            frame->is_application_error = true;
        } else {
            return false;
        }

        if (!varint_decode(iob, &frame->ec)) {
            return false;
        }

        uint64_t len = 0;
        if (!varint_decode(iob, &len)) {
            return false;
        }
        frame->reason.resize(len);
        if (!read_string_from_iob(iob, frame->reason)) {
            return false;
        }

        return true;
    }

    int32_t length_datagram_frame(const datagram_frame *frame) {
        if (frame->len_present) {
            return 1 + varint_length(frame->data.size()) + frame->data.size();
        } else {
            return 1 + frame->data.size();
        }
    }

    bool pack_datagram_frame(const datagram_frame *frame, io_buffer *iob) {
        frame_type tp = FT_DATAGRAM;
        if (frame->len_present) {
            tp = FT_DATAGRAM_LEN_PRESENT;
        }
        if (!iob->write(tp)) {
            return false;
        }

        if (frame->len_present) {
            if (!varint_encode(frame->data.size(), iob)) {
            return false;
            }
        }
        
        if (!write_string_to_iob(frame->data, iob)) {
            return false;
        }

        return true;
    }

    bool unpack_datagram_frame(io_buffer *iob, datagram_frame *frame) {
        frame_type tp;
        if (!iob->read((block_t*)&tp)) {
            return false;
        }
        
        int32_t len = 0;
        if (tp == FT_DATAGRAM) {
            len = iob->size();
        } else if (tp == FT_DATAGRAM_LEN_PRESENT) {
            frame->len_present = true;
            if (!varint_decode_ex(iob, &len)) {
                return false;
            }
        }

        frame->data.resize(len);
        if (!read_string_from_iob(iob, frame->data)) {
            return false;
        }

        return true;
    }

}
}
}