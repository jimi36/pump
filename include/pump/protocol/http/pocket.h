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

#ifndef pump_protocol_http_pocket_h
#define pump_protocol_http_pocket_h

#include "pump/protocol/http/uri.h"
#include "pump/protocol/http/header.h"
#include "pump/protocol/http/content.h"

namespace pump {
namespace protocol {
    namespace http {

        enum pocket_type { PK_UNKNOWN = 0, PK_REQUEST, PK_RESPONSE };

        enum protocol_version { VERSION_UNKNOWN = 0, VERSION_10, VERSION_11, VERSION_20 };

        enum pocket_parse_status {
            PARSE_NONE = 0,
            PARSE_LINE,
            PARSE_HEADER,
            PARSE_CONTENT,
            PARSE_FINISHED,
            PARSE_FAILED
        };

        class LIB_PUMP pocket {
          public:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            pocket(pocket_type pt) noexcept
                : pt_(pt),
                  parse_status_(PARSE_NONE),
                  version_(VERSION_UNKNOWN),
                  ct_(nullptr) {
            }

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            virtual ~pocket() = default;

            /*********************************************************************************
             * Get pocket type
             ********************************************************************************/
            PUMP_INLINE pocket_type get_type() const {
                return pt_;
            }

            /*********************************************************************************
             * Parse
             * This parse http pocket, and return parsed size. If this return -1, it
             *means parsed error.
             ********************************************************************************/
            virtual int32 parse(c_block_ptr b, int32 size) = 0;

            /*********************************************************************************
             * Serialize
             * This serialize http pocket and return serialized size.
             ********************************************************************************/
            virtual int32 serialize(std::string &buffer) const = 0;

            /*********************************************************************************
             * Get http header
             ********************************************************************************/
            PUMP_INLINE const header_ptr get_header() const {
                return (const header_ptr)&header_;
            }
            PUMP_INLINE header_ptr get_header() {
                return &header_;
            }

            /*********************************************************************************
             * Set http content
             ********************************************************************************/
            PUMP_INLINE void set_content(content_sptr &content) {
                ct_ = content;
            }

            /*********************************************************************************
             * Get http content
             ********************************************************************************/
            PUMP_INLINE const content_sptr get_content() const {
                return ct_;
            }

            /*********************************************************************************
             * Set http version
             ********************************************************************************/
            PUMP_INLINE void set_http_version(protocol_version version) {
                version_ = version;
            }

            /*********************************************************************************
             * Get http version
             ********************************************************************************/
            PUMP_INLINE protocol_version get_http_version() const {
                return version_;
            }

            /*********************************************************************************
             * Get http version string
             ********************************************************************************/
            PUMP_INLINE std::string get_http_version_string() const {
                if (version_ == VERSION_10)
                    return "HTTP/1.0";
                else if (version_ == VERSION_11)
                    return "HTTP/1.1";
                else if (version_ == VERSION_20)
                    return "HTTP/2.0";
                else
                    return "";
            }

            /*********************************************************************************
             * Check parse finished or not
             ********************************************************************************/
            PUMP_INLINE bool is_parse_finished() const {
                return parse_status_ == PARSE_FINISHED;
            }

          protected:
            // Pocket type
            pocket_type pt_;
            // Parse status
            pocket_parse_status parse_status_;
            // Http version
            protocol_version version_;
            // Http header
            header header_;
            // Http content
            content_sptr ct_;
        };
        DEFINE_ALL_POINTER_TYPE(pocket);

    }  // namespace http
}  // namespace protocol
}  // namespace pump

#endif