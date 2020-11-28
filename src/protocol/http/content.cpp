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

#include "pump/protocol/http/content.h"

namespace pump {
namespace protocol {
    namespace http {

        content::content() noexcept
          : parse_finished_(false),
            is_chunked_(false),
            next_chunk_size_(0),
            length_(0) {
        }

        void content::append(const block_t *b, int32_t size) {
            data_.append(b, size);
        }

        void content::append(const std::string &data) {
            data_.append(data);
        }

        int32_t content::serialize(std::string &buf) const {
            if (is_chunked_) {
                int32_t size = 0;
                block_t tmp[32] = {0};
                size = snprintf(tmp, sizeof(tmp), "%zx%s", data_.size(), HTTP_CR);

                buf.append(tmp).append(data_).append(HTTP_CR);
                size += (int32_t)data_.size() + HTTP_CR_LEN;

                return size;
            } else {
                if (data_.empty()) {
                    return 0;
                }

                buf.append(data_);

                return (int32_t)data_.size();
            }
        }

        int32_t content::parse(const block_t *b, int32_t size) {
            if (is_chunked_) {
                return __parse_by_chunk(b, size);
            } else {
                return __parse_by_length(b, size);
            }
        }

        int32_t content::__parse_by_length(const block_t *b, int32_t size) {
            int32_t want_parse_size = length_ - (int32_t)data_.size();
            if (want_parse_size > size) {
                want_parse_size = size;
            }
            data_.append(b, want_parse_size);

            if ((int32_t)data_.size() == length_) {
                parse_finished_ = true;
            }

            return want_parse_size;
        }

        int32_t content::__parse_by_chunk(const block_t *b, int32_t size) {
            const block_t *pos = b;

            while (1) {
                const block_t *chunk_pos = pos;
                const block_t *line_end =
                    find_http_line_end(chunk_pos, size - int32_t(chunk_pos - b));
                if (!line_end) {
                    break;
                }

                line_end -= HTTP_CR_LEN;
                int32_t next_chunk_size = 0;
                while (chunk_pos != line_end) {
                    next_chunk_size =
                        next_chunk_size * 16 + hexchar_to_decnum(*(chunk_pos++));
                }
                chunk_pos += HTTP_CR_LEN;

                if (next_chunk_size == 0) {
                    if (chunk_pos + HTTP_CR_LEN > b + size) {
                        break;
                    }

                    if (memcmp(chunk_pos, HTTP_CR, HTTP_CR_LEN) != 0) {
                        return -1;
                    }

                    pos = chunk_pos + HTTP_CR_LEN;
                    parse_finished_ = true;
                    break;
                }

                if (chunk_pos + next_chunk_size + HTTP_CR_LEN > b + size) {
                    break;
                }
                data_.append(chunk_pos, next_chunk_size);

                pos = chunk_pos + next_chunk_size + HTTP_CR_LEN;
            }

            return int32_t(pos - b);
        }

    }  // namespace http
}  // namespace protocol
}  // namespace pump