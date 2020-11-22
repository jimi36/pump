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

#ifndef pump_protocol_http_content_h
#define pump_protocol_http_content_h

#include "pump/protocol/http/utils.h"

namespace pump {
namespace protocol {
    namespace http {

        class LIB_PUMP content {

          public:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            content() noexcept;

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            ~content() = default;

            /*********************************************************************************
             * Set chunked mode
             ********************************************************************************/
            PUMP_INLINE void set_chunked() {
                is_chunked_ = true;
            }

            /*********************************************************************************
             * Append data
             ********************************************************************************/
            void append(c_block_ptr b, int32 size);
            void append(const std::string &data);

            /*********************************************************************************
             * Parse
             * This return parsed size. If return -1, it means parse error.
             ********************************************************************************/
            int32 parse(c_block_ptr b, int32 size);

            /*********************************************************************************
             * Serialize
             ********************************************************************************/
            int32 serialize(std::string &buf) const;

            /*********************************************************************************
             * Get data
             ********************************************************************************/
            PUMP_INLINE const std::string &data() const {
                return data_;
            }

            /*********************************************************************************
             * Set content length to parse
             * If chunked mode is set, content length will be ignore.
             ********************************************************************************/
            PUMP_INLINE void set_length_to_parse(int32 len) {
                length_ = len;
            }

            /*********************************************************************************
             * Check parse is finished or not
             ********************************************************************************/
            PUMP_INLINE bool is_parse_finished() const {
                return parse_finished_;
            }

          private:
            /*********************************************************************************
             * Parse content by content length
             ********************************************************************************/
            int32 __parse_by_length(c_block_ptr b, int32 size);

            /*********************************************************************************
             * Parse content by chunk mode
             ********************************************************************************/
            int32 __parse_by_chunk(c_block_ptr b, int32 size);

          private:
            // Parse finished mark
            bool parse_finished_;
            // Chunk mode mark
            bool is_chunked_;
            // Next chunk size for chunk mode
            int32 next_chunk_size_;
            // Content data
            std::string data_;
            // Content length
            // If chunk mode is set, this will be ignore.
            int32 length_;
        };
        DEFINE_ALL_POINTER_TYPE(content);

    }  // namespace http
}  // namespace protocol
}  // namespace pump

#endif