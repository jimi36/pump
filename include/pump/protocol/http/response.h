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

#ifndef pump_protocol_http_response_h
#define pump_protocol_http_response_h

#include "pump/protocol/http/pocket.h"

namespace pump {
namespace protocol {
namespace http {

    class LIB_PUMP response
      : public pocket {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        response() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~response() = default;

        /*********************************************************************************
         * Set status code
         ********************************************************************************/
        PUMP_INLINE void set_status_code(int32_t status_code) {
            status_code_ = status_code;
        }

        /*********************************************************************************
         * Get response status code
         ********************************************************************************/
        PUMP_INLINE int32_t get_status_code() const {
            return status_code_;
        }

        /*********************************************************************************
         * Parse
         * This parse http pocket, and return parsed size. 
         * If parsed error, return -1.
         ********************************************************************************/
        virtual int32_t parse(
            const block_t *b, 
            int32_t size) override;

        /*********************************************************************************
         * Serialize
         * This will serialize http response and return serialized size.
         ********************************************************************************/
        virtual int32_t serialize(std::string &buffer) const override;

      private:
        /*********************************************************************************
         * Parse http start line
         ********************************************************************************/
        int32_t __parse_start_line(
            const block_t *b, 
            int32_t size);

        /*********************************************************************************
         * Serialize http response line
         ********************************************************************************/
        int32_t __serialize_response_line(std::string &buffer) const;

      private:
        // Status code
        int32_t status_code_;
    };
    DEFINE_ALL_POINTER_TYPE(response);

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif