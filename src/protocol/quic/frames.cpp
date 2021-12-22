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
#include "pump/protocol/quic/varint.h"
#include "pump/protocol/quic/frames.h"
#include "pump/protocol/quic/parameters.h"

namespace pump {
namespace protocol {
namespace quic {

    int32_t encode_padding_frame(const padding_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1) {
            return -1;
        }
        b[0] = FT_PADDING;

        return 1;
    }

    int32_t decode_padding_frame(const block_t *b, int32_t blen, padding_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1 || b[0] == FT_PADDING) {
            return -1;
        }

        return 1;
    }

    int32_t length_padding_frame(const padding_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1;
    }

    int32_t encode_ping_frame(const ping_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1) {
            return -1;
        }
        b[0] = FT_PING;

        return 1;
    }

    int32_t decode_ping_frame(const block_t *b, int32_t blen, ping_frame *frame){
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1 || b[0] == FT_PING) {
            return -1;
        }

        return 1;
    }

    int32_t length_ping_frame(const ping_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1;
    }

    uint64_t __encode_ack_delay(uint64_t ack_delay, int32_t ack_delay_export) {
        if (ack_delay_export <= 0) {
            ack_delay_export = DEF_ACK_DELAY_EXPONENT;
        }
        return ack_delay / (1 << ack_delay_export);
    }

    uint64_t __decode_ack_delay(uint64_t delay, int32_t ack_delay_export) {
        if (ack_delay_export <= 0) {
            ack_delay_export = DEF_ACK_DELAY_EXPONENT;
        }
        return delay * (1 << ack_delay_export);
    }

    uint32_t __ack_range_count(const ack_frame *frame) {
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

    int32_t encode_ack_frame(const ack_frame *frame, block_t *b, int32_t blen){
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        if (frame->ect0 > 0 || frame->ect1 > 0 || frame->ecnce > 0) {
            *(p++) = FT_ACK_ECN;
        } else {
            *(p++) = FT_ACK;
        }

        uint32_t range_count = __ack_range_count(frame);
        uint64_t first_range = frame->ack_ranges[0].largest - frame->ack_ranges[0].smallest;
        uint64_t ack_delay = __encode_ack_delay(frame->ack_delay, frame->ack_delay_export);
        if ((p = varint_encode(p, int32_t(e - p), frame->ack_ranges[0].largest)) == nullptr || 
            (p = varint_encode(p, int32_t(e - p), ack_delay)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), range_count)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), first_range)) == nullptr) {
            return -1;
        }

        for (uint32_t i = 1; i <= range_count; i++) {
            uint64_t gap = frame->ack_ranges[i - 1].smallest - frame->ack_ranges[i].largest - 2;
            uint64_t len = frame->ack_ranges[i].largest - frame->ack_ranges[i].smallest;
            if ((p = varint_encode(p, int32_t(e - p), gap)) == nullptr || 
                (p = varint_encode(p, int32_t(e - p), len)) == nullptr) {
                return -1;
            }
        }

        if (b[0] == FT_ACK_ECN) {
            if ((p = varint_encode(p, int32_t(e - p), frame->ect0)) == nullptr || 
                (p = varint_encode(p, int32_t(e - p), frame->ect1)) == nullptr ||
                (p = varint_encode(p, int32_t(e - p), frame->ecnce)) == nullptr) {
                return -1;
            }
        }

        return int32_t(p - b);
    }

    int32_t decode_ack_frame(const block_t *b, int32_t blen, ack_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || (*p != FT_ACK && *p != FT_ACK_ECN)) {
            return -1;
        }
        p += 1;

        uint64_t largest_ack = 0;
        if ((p = varint_decode(p, int32_t(e - p), largest_ack)) == nullptr) {
            return -1;
        }

        uint64_t delay = 0;
        if ((p = varint_decode(p, int32_t(e - p), delay)) == nullptr) {
            return -1;
        }
        frame->ack_delay = __decode_ack_delay(delay, frame->ack_delay_export);

        uint64_t range_count = 0;
        if ((p = varint_decode(p, int32_t(e - p), range_count)) == nullptr) {
            return -1;
        }

        uint64_t first_range = 0;
        if ((p = varint_decode(p, int32_t(e - p), first_range)) == nullptr ||
            first_range > largest_ack) {
            return -1;
        }
        uint64_t smallest = largest_ack - first_range;
        frame->ack_ranges.push_back(ack_range{smallest, largest_ack});

        for (uint64_t i = 0; i < range_count; i++) {
            uint64_t gap = 0;
            if ((p = varint_decode(p, int32_t(e - p), gap)) == nullptr) {
                return -1;
            }
            
            uint64_t len = 0;
            if ((p = varint_decode(p, int32_t(e - p), len)) == nullptr) {
                return -1;
            }

            uint64_t largest = smallest - gap - 2;
            if (len > largest) {
                return -1;
            }

            smallest = largest - len;
            frame->ack_ranges.push_back(ack_range{smallest, largest});
        }

        if (b[0] == FT_ACK_ECN) {
            if ((p = varint_decode(p, int32_t(e - p), frame->ect0)) == nullptr ||
                (p = varint_decode(p, int32_t(e - p), frame->ect1)) == nullptr ||
                (p = varint_decode(p, int32_t(e - p), frame->ecnce)) == nullptr) {
                return -1;
            }
        }

        return int32_t(p - b);
    }

    int32_t length_ack_frame(const ack_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

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

    int32_t encode_reset_stream_frame(const reset_stream_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_RESET_STREAM;

        if ((p = varint_encode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->error_code)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->final_size)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_reset_stream_frame(const block_t *b, int32_t blen, reset_stream_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_RESET_STREAM) {
            return -1;
        }

        if ((p =varint_decode(p, int32_t(e - p), frame->stream_id)) == nullptr || 
            (p =varint_decode(p, int32_t(e - p), frame->error_code)) == nullptr || 
            (p =varint_decode(p, int32_t(e - p), frame->final_size)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_reset_stream_frame(const reset_stream_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        int32_t len = 1;
        len += varint_length(frame->stream_id);
        len += varint_length(frame->error_code);
        len += varint_length(frame->final_size);
        return len;
    }

    int32_t encode_stop_sending_frame(const stop_sending_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_STOP_SENDING;

        if ((p = varint_encode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->error_code)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_stop_sending_frame(const block_t *b, int32_t blen, stop_sending_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if ( p >= e || *(p++) != FT_STOP_SENDING) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p =varint_decode(p, int32_t(e - p), frame->error_code)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_stop_sending_frame(const stop_sending_frame *frame){
        PUMP_ASSERT(frame != nullptr);

        int32_t len = 1;
        len += varint_length(frame->stream_id);
        len += varint_length(frame->error_code);
        return len;
    }

    int32_t encode_crypto_frame(const crypto_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_CRYPTO;

        if ((p = varint_encode(p, int32_t(e - p), frame->offset)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->data.size())) == nullptr) {
            return -1;
        }

        if (p + frame->data.size() > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->data.data(), frame->data.size()) + frame->data.size();

        return int32_t(p - b);
    }

    int32_t decode_crypto_frame(const block_t *b, int32_t blen, crypto_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_CRYPTO) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->offset)) == nullptr) {
            return -1;
        }

        int32_t len = 0;
        if ((p = varint_decode_ex(p, int32_t(e - p), len)) == nullptr) {
            return -1;
        } else if (len < 0 || p + len > e) {
            return -1;
        }
        frame->data.assign(p, len);
        p += len;

        return int32_t(p - b);
    }

    int32_t length_crypto_frame(const crypto_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        int32_t len = 1;
        len += varint_length(frame->offset);
        len += varint_length(frame->data.size());
        len += (int32_t)frame->data.size();
        return len;
    }

    int32_t encode_new_token_frame(const new_token_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_NEW_TOKEN;

        if ((p = varint_encode(p, int32_t(e - p), frame->token.size())) == nullptr) {
            return -1;
        }

        if (p + frame->token.size() > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->token.data(), frame->token.size()) + frame->token.size();

        return int32_t(p - b);
    }

    int32_t decode_new_token_frame(const block_t *b, int32_t blen, new_token_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_NEW_TOKEN) {
            return -1;
        }

        int32_t len = 0;
        if ((p = varint_decode_ex(p, int32_t(e - p), len)) == nullptr) {
            return -1;
        } else if (len < 0 || p + len > e) {
            return -1;
        }
        frame->token.assign(p, len);
        p += len;

        return int32_t(p - b);
    }

    int32_t length_new_token_frame(const new_token_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        int32_t len = 1;
        len += varint_length(frame->token.size());
        len += (int32_t)frame->token.size();
        return len;
    }

    int32_t encode_stream_frame(const stream_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        block_t ft = FT_STREAM;
        if (frame->stream_fin) {
            ft |= 0x01;
        }
        if (frame->has_data_len) {
            ft |= 0x02;
        }
        if (frame->has_offset) {
            ft |= 0x04;
        }
        if (p >= e) {
            return -1;
        }
        *(p++) = ft;

        if ((p = varint_encode(p, int32_t(e - p), frame->stream_id)) == nullptr) {
            return -1;
        }

        if (frame->has_offset && (p = varint_encode(p, int32_t(e - p), frame->offset)) == nullptr) {
            return -1;
        }

        if (frame->has_data_len && (p = varint_encode(p, int32_t(e - p), frame->data.size())) == nullptr) {
            return -1;
        }

        if (p + frame->data.size() > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->data.data(), frame->data.size()) + frame->data.size();

        return int32_t(p - b);
    }

    int32_t decode_stream_frame(const block_t *b, int32_t blen, stream_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }

        block_t ft = *(p++);
        if (ft < FT_STREAM) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->stream_id)) == nullptr) {
            return -1;
        }

        frame->stream_fin = false;
        if (ft && 0x01) {
            frame->stream_fin = true;
        }

        if (ft & 0x02 && (p = varint_decode(p, int32_t(e - p), frame->offset)) == nullptr) {
            return -1;
        }

        int32_t data_len = int32_t(e - p);
        if (ft & 0x04 && (p = varint_decode_ex(p, int32_t(e - p), data_len)) == nullptr) {
            return -1;
        }
        frame->data.assign(p, data_len);
        p += data_len;

        return int32_t(p - b);
    }

    int32_t length_stream_frame(const stream_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

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

    int32_t encode_max_data_frame(const max_data_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_MAX_DATA;

        if ((p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_max_data_frame(const block_t *b, int32_t blen, max_data_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_MAX_DATA) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_max_data_frame(const max_data_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->max);
    }

    int32_t encode_max_stream_data_frame(const max_stream_data_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_MAX_STREAM_DATA;

        if ((p = varint_encode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_max_stream_data_frame(const block_t *b, int32_t blen, max_stream_data_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_MAX_STREAM_DATA) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_max_stream_data_frame(const max_stream_data_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->stream_id) + varint_length(frame->max);
    }

    int32_t encode_max_streams_frame(const max_streams_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        if (frame->st == stream_bidirection) {
            *(p++) = FT_MAX_BIDISTREAMS;
        } else {
            *(p++) = FT_MAX_UNISTREAMS;
        }
        
        if ((p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_max_streams_frame(const block_t *b, int32_t blen, max_streams_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        block_t ft = *(p++);
        if (ft == FT_MAX_BIDISTREAMS) {
            frame->st = stream_bidirection;
        } else if (ft == FT_MAX_UNISTREAMS) {
            frame->st = stream_unidirection;
        } else {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_max_streams_frame(const max_streams_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->max);
    }

    int32_t encode_data_blocked_frame(const data_blocked_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_DATA_BLOCKED;

        if ((p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_data_blocked_frame(const block_t *b, int32_t blen, data_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_DATA_BLOCKED) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_data_blocked_frame(const data_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->max);
    }

    int32_t encode_stream_data_blocked_frame(const stream_data_blocked_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_STREAM_DATA_BLOCKED;

        if ((p = varint_encode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_stream_data_blocked_frame(const block_t *b, int32_t blen, stream_data_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_STREAM_DATA_BLOCKED) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->stream_id)) == nullptr ||
            (p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_stream_data_blocked_frame(const stream_data_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->stream_id) + varint_length(frame->max);
    }

    int32_t encode_streams_blocked_frame(const streams_blocked_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        if (frame->st == stream_bidirection) {
            *(p++) = FT_BIDISTREAMS_BLOCKED;
        } else {
            *(p++) = FT_UNISTREAMS_BLOCKED;
        }

        if ((p = varint_encode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_streams_blocked_frame(const block_t *b, int32_t blen, streams_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        block_t ft = *(p++);
        if (ft == FT_BIDISTREAMS_BLOCKED) {
            frame->st = stream_bidirection;
        } else if (ft == FT_UNISTREAMS_BLOCKED) {
            frame->st = stream_unidirection;
        } else {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->max)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_streams_blocked_frame(const streams_blocked_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->max);
    }

    int32_t encode_new_connection_id_frame(const new_connection_id_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_NEW_CONNECTION_ID;

        if ((p = varint_encode(p, int32_t(e - p), frame->seq)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->retire_prior_to)) == nullptr ||
            (p = varint_encode(p, int32_t(e - p), frame->id.length())) == nullptr) {
            return -1;
        }

        const std::string &id = frame->id.id();
        if (p + id.size() > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, id.c_str(), id.size()) + frame->id.length();

        if (p + sizeof(frame->stateless_reset_token) > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->stateless_reset_token, sizeof(frame->stateless_reset_token)) + sizeof(frame->stateless_reset_token);

        return int32_t(p - b);
    }

    int32_t decode_new_connection_id_frame(const block_t *b, int32_t blen, new_connection_id_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_NEW_CONNECTION_ID) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->seq)) == nullptr ||
            (p = varint_decode(p, int32_t(e - p), frame->retire_prior_to)) == nullptr) {
            return -1;
        }

        int32_t len = 0;
        if ((p = varint_decode_ex(p, int32_t(e - p), len)) == nullptr) {
            return -1;
        } else if (len <= 0 || p + len > e) {
            return -1;
        }
        frame->id = cid(p, len);
        p += len;

        if (p + sizeof(frame->stateless_reset_token) > e) {
            return -1;
        }
        p = (const block_t*)memcpy(frame->stateless_reset_token, p, sizeof(frame->stateless_reset_token)) + sizeof(frame->stateless_reset_token);

        return int32_t(p - b);
    }

    int32_t length_new_connection_id_frame(const new_connection_id_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        int32_t len = 1;
        len += varint_length(frame->seq);
        len += varint_length(frame->retire_prior_to);
        len += varint_length(frame->id.length()) + frame->id.length();
        len += sizeof(frame->stateless_reset_token);
        return len;
    }

    int32_t encode_retire_connection_id_frame(const retire_connection_id_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_RETIRE_CONNECTION_ID;

        if ((p = varint_encode(p, int32_t(e - p), frame->seq)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t decode_retire_connection_id_frame(const block_t *b, int32_t blen, retire_connection_id_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_RETIRE_CONNECTION_ID) {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->seq)) == nullptr) {
            return -1;
        }

        return int32_t(p - b);
    }

    int32_t length_retire_connection_id_frame(const retire_connection_id_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->seq);
    }

    int32_t encode_path_challenge_frame(const path_challenge_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_PATH_CHALLENGE;

        if (p + sizeof(frame->data) > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->data, sizeof(frame->data)) + sizeof(frame->data);

        return int32_t(p - b);
    }

    int32_t decode_path_challenge_frame(const block_t *b, int32_t blen, path_challenge_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (frame == nullptr || b == nullptr || blen < 1) {
            return -1;
        }

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_PATH_CHALLENGE) {
            return -1;
        }

        if (p + sizeof(frame->data) > e) {
            return -1;
        }
        p = (const block_t*)memcpy(frame->data, p, sizeof(frame->data)) + sizeof(frame->data);

        return int32_t(p - b);
    }

    int32_t length_path_challenge_frame(const path_challenge_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + sizeof(frame->data);
    }

    int32_t encode_path_response_frame(const path_response_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        *(p++) = FT_PATH_RESPONSE;

        if (p + sizeof(frame->data) > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->data, sizeof(frame->data)) + sizeof(frame->data);

        return int32_t(p - b);
    }

    int32_t decode_path_response_frame(const block_t *b, int32_t blen, path_response_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (frame == nullptr || b == nullptr || blen < 1) {
            return -1;
        }

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e || *(p++) != FT_PATH_RESPONSE) {
            return -1;
        }

        if (p + sizeof(frame->data) > e) {
            return -1;
        }
        p = (const block_t*)memcpy(frame->data, p, sizeof(frame->data)) + sizeof(frame->data);

        return int32_t(p - b);
    }

    int32_t length_path_response_frame(const path_response_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + sizeof(frame->data);
    }

    int32_t encode_connection_close_frame(const connection_close_frame *frame, block_t *b, int32_t blen){
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        block_t *p = b;
        block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }
        if (frame->is_application_error) {
            *(p++) = FT_A_CONNECTION_CLOSE;
        } else {
            *(p++) = FT_Q_CONNECTION_CLOSE;
        }
        
        if ((p = varint_encode(p, int32_t(e - p), frame->ec)) == nullptr) {
            return -1;
        }

        if ((p = varint_encode(p, int32_t(e - p), frame->reason.size())) == nullptr) {
            return -1;
        }

        if (p + frame->reason.size() > e) {
            return -1;
        }
        p = (block_t*)memcpy(p, frame->reason.data(), frame->reason.size()) +  frame->reason.size();

        return int32_t(p - b);
    }

    int32_t decode_connection_close_frame(const block_t *b, int32_t blen, connection_close_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        const block_t *p = b;
        const block_t *e = b + blen;

        if (p >= e) {
            return -1;
        }

        frame_type ft = *(p++); 
        if (ft == FT_Q_CONNECTION_CLOSE) {
            frame->is_application_error = false;
        } else if (ft == FT_A_CONNECTION_CLOSE) {
            frame->is_application_error = true;
        } else {
            return -1;
        }

        if ((p = varint_decode(p, int32_t(e - p), frame->ec)) == nullptr) {
            return -1;
        }

        uint64_t len = 0;
        if ((p = varint_decode(p, int32_t(e - p), len)) == nullptr) {
            return -1;
        }

        if (p + len > e) {
            return -1;
        }
        frame->reason.resize(len);
        p = (block_t*)memcpy((void*)frame->reason.data(), p, len) + len;

        return int32_t(p - b);
    }

    int32_t length_connection_close_frame(const connection_close_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1 + varint_length(frame->ec) + varint_length(frame->reason.size()) + frame->reason.size();
    }

    int32_t encode_handshake_done_frame(const handshake_done_frame *frame, block_t *b, int32_t blen) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1) {
            return -1;
        }
        b[0] = FT_HANDSHAKE_DONE;

        return 1;
    }

    int32_t decode_handshake_done_frame(const block_t *b, int32_t blen, handshake_done_frame *frame) {
        PUMP_ASSERT(frame != nullptr && b != nullptr);

        if (blen < 1 || b[0] == FT_HANDSHAKE_DONE) {
            return -1;
        }

        return 1;
    }

    int32_t length_handshake_done_frame(const handshake_done_frame *frame) {
        PUMP_ASSERT(frame != nullptr);

        return 1;
    }

}
}
}