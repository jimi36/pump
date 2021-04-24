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

#ifndef pump_protocol_http_body_h
#define pump_protocol_http_body_h

#include "pump/protocol/http/utils.h"

namespace pump {
namespace protocol {
namespace http {

    class LIB_PUMP body {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        body() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~body() = default;

        /*********************************************************************************
         * Set chunked mode
         ********************************************************************************/
        PUMP_INLINE void set_chunked() {
            is_chunk_mode_ = true;
        }

        /*********************************************************************************
         * Append data
         ********************************************************************************/
        PUMP_INLINE void append(const std::string &data) {
            data_.append(data);
        }
        PUMP_INLINE void append(
            const block_t *b, 
            int32_t size) {
            data_.append(b, size);
        }

        /*********************************************************************************
         * Parse
         * This return parsed size. If return -1, it means parse error.
         ********************************************************************************/
        int32_t parse(
            const block_t *b, 
            int32_t size);

        /*********************************************************************************
         * Serialize
         ********************************************************************************/
        int32_t serialize(std::string &buf) const;

        /*********************************************************************************
         * Get data
         ********************************************************************************/
        PUMP_INLINE const std::string &data() const {
            return data_;
        }

        /*********************************************************************************
         * Set body content length
         * If using chunked mode, content length will be ignore.
         ********************************************************************************/
        PUMP_INLINE void set_length(int32_t len) {
            content_length_ = len;
        }

        /*********************************************************************************
         * Check parse is finished or not
         ********************************************************************************/
        PUMP_INLINE bool is_parse_finished() const {
            return parse_finished_;
        }

      private:
        /*********************************************************************************
         * Parse body by content length mode
         ********************************************************************************/
        int32_t __parse_by_length(
            const block_t *b, 
            int32_t size);

        /*********************************************************************************
         * Parse body by chunk mode
         ********************************************************************************/
        int32_t __parse_by_chunk(
            const block_t *b, 
            int32_t size);

      private:
        // Parse finished mark
        bool parse_finished_;

        // Body data
        std::string data_;

        // Chunk mode flag
        bool is_chunk_mode_;
   
        // Content length
        // Ignore if using chunked mode.
        int32_t content_length_;
    };
    DEFINE_ALL_POINTER_TYPE(body);

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif