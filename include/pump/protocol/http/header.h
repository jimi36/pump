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

#ifndef pump_protocol_http_header_h
#define pump_protocol_http_header_h

#include <map>

#include "pump/protocol/http/utils.h"

namespace pump {
namespace protocol {
    namespace http {

        class LIB_PUMP header {
          public:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            header() noexcept;

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            ~header() = default;

            /*********************************************************************************
             * Parse
             * This parse http header and return parsed size. If this return -1, it
             *means parsed error.
             ********************************************************************************/
            int32 parse(c_block_ptr b, int32 size);

            /*********************************************************************************
             * Serialize
             * This will serialize http header and end CR(\r\n), then return serialized
             *size.
             ********************************************************************************/
            int32 serialize(std::string &buf) const;

            /*********************************************************************************
             * Set http header
             * If the header field with the name has existed, the value will append to
             *the existed value.
             ********************************************************************************/
            void set(const std::string &name, int32 value);
            void set(const std::string &name, const std::string &value);

            /*********************************************************************************
             * Set http header
             * If the header field has existed, the field vaule will be replace.
             ********************************************************************************/
            void set_unique(const std::string &name, int32 value);
            void set_unique(const std::string &name, const std::string &value);

            /*********************************************************************************
             * Get http header
             ********************************************************************************/
            bool get(const std::string &name, int32 &value) const;
            bool get(const std::string &name, std::string &value) const;
            bool get(const std::string &name, std::vector<std::string> &values) const;

            /*********************************************************************************
             * Check header field existed or not
             ********************************************************************************/
            bool has(const std::string &name) const;

            /*********************************************************************************
             * Check parse is finished or not
             ********************************************************************************/
            PUMP_INLINE bool is_parse_finished() const {
                return parse_finished_;
            }

          private:
            // Parse finished mark
            bool parse_finished_;
            // Http header map
            std::map<std::string, std::vector<std::string> > headers_;
        };
        DEFINE_ALL_POINTER_TYPE(header);

    }  // namespace http
}  // namespace protocol
}  // namespace pump

#endif