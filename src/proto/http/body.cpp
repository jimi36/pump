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
#include "pump/proto/http/body.h"

namespace pump {
namespace proto {
namespace http {

body::body() noexcept
  : is_chunk_mode_(false),
    expected_size_(0),
    parsing_chunk_size_(0),
    is_parse_finished_(false) {
}

int32_t body::serialize(std::string &buf) const {
    if (is_chunk_mode_) {
        char chunk_len[64] = {0};
        int32_t size = snprintf(
            chunk_len,
            sizeof(chunk_len) - 1,
            "%zx%s",
            data_.size(),
            http_crlf);
        buf.append(chunk_len).append(data_).append(http_crlf);
        return size + (int32_t)data_.size() + http_crlf_length;
    } else {
        if (data_.empty()) {
            return 0;
        }
        buf.append(data_);
        return (int32_t)data_.size();
    }
}

int32_t body::parse(const char *b, int32_t size) {
    if (is_chunk_mode_) {
        return __parse_by_chunk(b, size);
    } else {
        return __parse_by_length(b, size);
    }
}

int32_t body::__parse_by_length(const char *b, int32_t size) {
    auto parse_size = expected_size_ - (int32_t)data_.size();
    if (parse_size > size) {
        parse_size = size;
    }

    data_.append(b, parse_size);

    if ((int32_t)data_.size() == expected_size_) {
        is_parse_finished_ = true;
    }

    return parse_size;
}

int32_t body::__parse_by_chunk(const char *b, int32_t size) {
    auto pos = b;
    auto end = b + size;

    while (pos < end) {
        if (parsing_chunk_size_ == 0) {
            auto size_pos = pos;
            int32_t chunk_size = 0;

            // Parse current chunk size.
            while (size_pos < end) {
                if (chunk_size >= 1048576) {  // 1MB
                    pump_warn_log("http chunk body size %d is too long", chunk_size);
                    return -1;
                }
                if (*size_pos == http_crlf[0]) {
                    if (size_pos + http_crlf_length > end) {
                        return int32_t(pos - b);
                    } else if (*(size_pos + 1) != http_crlf[1]) {
                        pump_warn_log("http chunk size line invalid");
                        return -1;
                    }
                    size_pos += http_crlf_length;
                    break;
                }
                chunk_size = chunk_size * 16 + hex_to_dec(*(size_pos++));
            }

            // Update expected body size.
            expected_size_ += chunk_size;

            // Save current parsing chunk size.
            parsing_chunk_size_ = chunk_size;

            // If chunk size is zero, parse finished.
            if (parsing_chunk_size_ == 0) {
                if (size_pos + http_crlf_length > end) {
                    break;
                } else if (size_pos[0] != http_crlf[0] ||
                           size_pos[1] != http_crlf[1]) {
                    pump_warn_log("http chunk body invalid");
                    return -1;
                }

                pump_assert(int32_t(data_.size()) == expected_size_);

                pos = size_pos + http_crlf_length;

                // Mark parse finished flag.
                is_parse_finished_ = true;

                break;
            }

            parsing_chunk_size_ += http_crlf_length;

            pos = size_pos;
        }

        int32_t left_size = end - pos;
        int32_t diff = left_size - parsing_chunk_size_;
        if (diff >= 0) {
            if (parsing_chunk_size_ > http_crlf_length) {
                data_.append(pos, parsing_chunk_size_ - http_crlf_length);
            }
            pos += parsing_chunk_size_;
            parsing_chunk_size_ = 0;
        } else {
            if (parsing_chunk_size_ == http_crlf_length) {
                break;
            }

            if (http_crlf_length <= -diff) {
                data_.append(pos, left_size);
                pos += left_size;
                parsing_chunk_size_ -= left_size;
            } else {
                data_.append(pos, parsing_chunk_size_ - http_crlf_length);
                pos += (parsing_chunk_size_ - http_crlf_length);
                parsing_chunk_size_ = http_crlf_length;
            }
        }
    }

    return int32_t(pos - b);
}

}  // namespace http
}  // namespace proto
}  // namespace pump
