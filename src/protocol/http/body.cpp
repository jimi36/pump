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
#include "pump/protocol/http/body.h"

namespace pump {
namespace protocol {
namespace http {

    body::body() noexcept
      : parse_finished_(false),
        expected_size_(0),
        is_chunk_mode_(false),
        parsing_chunk_size_(0) {
    }

    int32_t body::serialize(std::string &buf) const {
        if (is_chunk_mode_) {
            block_t chunk_len[64] = {0};
            int32_t size = snprintf(
                            chunk_len, 
                            sizeof(chunk_len) - 1, 
                            "%zx%s", 
                            data_.size(), 
                            HTTP_CRLF);
            buf.append(chunk_len).append(data_).append(HTTP_CRLF);
            return size + (int32_t)data_.size() + HTTP_CRLF_LEN;
        } else {
            if (data_.empty()) {
                return 0;
            }
            buf.append(data_);
            return (int32_t)data_.size();
        }
    }

    int32_t body::parse(const block_t *b, int32_t size) {
        if (is_chunk_mode_) {
            return __parse_by_chunk(b, size);
        } else {
            return __parse_by_length(b, size);
        }
    }

    int32_t body::__parse_by_length(const block_t *b, int32_t size) {
        int32_t want_parse_size = expected_size_ - (int32_t)data_.size();
        if (want_parse_size > size) {
            want_parse_size = size;
        }
        data_.append(b, want_parse_size);

        if ((int32_t)data_.size() == expected_size_) {
            parse_finished_ = true;
        }

        return want_parse_size;
    }

    int32_t body::__parse_by_chunk(const block_t *b, int32_t size) {
        auto pos = b;
        auto end = b + size;

        while (pos < end) {
            if (parsing_chunk_size_ == 0) {
                // Find chunk size field.
                auto size_field_end = find_http_line_end(pos, end - pos);
                if (size_field_end == nullptr) {
                    break;
                }

                // Parse chunk size.
                auto size_pos = pos;
                auto size_end = size_field_end - HTTP_CRLF_LEN;
                for (; size_pos != size_end; size_pos++) {
                    parsing_chunk_size_ = parsing_chunk_size_ * 16 + hex_to_dec(*size_pos);
                }

                expected_size_ += parsing_chunk_size_;

                // If chunk size is zero, finish parsing.
                if (parsing_chunk_size_ == 0) {
                    if (size_field_end + HTTP_CRLF_LEN > end) {
                        break;
                    } else if (memcmp(size_field_end, HTTP_CRLF, HTTP_CRLF_LEN) != 0) {
                        return -1;
                    }

                    PUMP_ASSERT(int32_t(data_.size()) == expected_size_);

                    pos = size_field_end + HTTP_CRLF_LEN;
                    parse_finished_ = true;
                    
                    break;
                }

                parsing_chunk_size_ += HTTP_CRLF_LEN;

                pos = size_field_end;
            }

            int32_t parsing_size = end - pos;
            int32_t diff = parsing_chunk_size_ - parsing_size;
            if (diff <= 0) {
                if (parsing_chunk_size_ > HTTP_CRLF_LEN) {
                    data_.append(pos, parsing_chunk_size_ - HTTP_CRLF_LEN);
                }
                pos += parsing_chunk_size_;
                parsing_chunk_size_ = 0;
            } else {
                if (parsing_chunk_size_ == HTTP_CRLF_LEN) {
                    break;
                }

                if (diff >= HTTP_CRLF_LEN) {
                    data_.append(pos, parsing_size);
                    pos += parsing_size;
                    parsing_chunk_size_ -= parsing_size;
                } else {
                    data_.append(pos, parsing_chunk_size_ - HTTP_CRLF_LEN);
                    pos += (parsing_chunk_size_ - HTTP_CRLF_LEN);
                    parsing_chunk_size_ = HTTP_CRLF_LEN;
                }
            }
        }

        return int32_t(pos - b);
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump