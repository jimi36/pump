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

#ifndef pump_proto_http_body_h
#define pump_proto_http_body_h

#include "pump/memory.h"
#include "pump/proto/http/utils.h"

namespace pump {
namespace proto {
namespace http {

class pump_lib body {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    body() pump_noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~body() = default;

    /*********************************************************************************
     * Set chunked mode
     ********************************************************************************/
    pump_inline void set_chunked() pump_noexcept {
        is_chunk_mode_ = true;
    }

    /*********************************************************************************
     * Append data
     ********************************************************************************/
    pump_inline void append(const std::string &data) {
        data_.append(data);
    }
    pump_inline void append(const char *b, int32_t size) {
        data_.append(b, size);
    }

    /*********************************************************************************
     * Parse
     * This return parsed size. If return -1, it means parse error.
     ********************************************************************************/
    int32_t parse(const char *b, int32_t size);

    /*********************************************************************************
     * Serialize
     ********************************************************************************/
    int32_t serialize(std::string &buf) const;

    /*********************************************************************************
     * Get data
     ********************************************************************************/
    pump_inline const std::string &data() const pump_noexcept {
        return data_;
    }

    /*********************************************************************************
     * Set expected data size
     ********************************************************************************/
    pump_inline void set_expected_size(int32_t size) pump_noexcept {
        expected_size_ = size;
    }

    /*********************************************************************************
     * Check parse status
     ********************************************************************************/
    pump_inline bool is_parse_finished() const pump_noexcept {
        return is_parse_finished_;
    }

  private:
    /*********************************************************************************
     * Parse body by content length mode
     ********************************************************************************/
    int32_t __parse_by_length(const char *b, int32_t size);

    /*********************************************************************************
     * Parse body by chunk mode
     ********************************************************************************/
    int32_t __parse_by_chunk(const char *b, int32_t size);

  private:
    // Chunk mode flag
    bool is_chunk_mode_;

    // Body data
    std::string data_;

    // Expected size
    int32_t expected_size_;

    // Parsing chunk size
    int32_t parsing_chunk_size_;

    // Parse finished flag
    bool is_parse_finished_;
};
DEFINE_SMART_POINTERS(body);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
