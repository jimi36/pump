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
#include "pump/protocol/http/body.h"
#include "pump/protocol/http/header.h"

namespace pump {
namespace protocol {
namespace http {

    /*********************************************************************************
     * Http Pocket type
     ********************************************************************************/
    const int32_t PK_UNKNOWN = 0;
    const int32_t PK_REQUEST = 1;
    const int32_t PK_RESPONSE = 2;

    /*********************************************************************************
     * Http version
     ********************************************************************************/
    const int32_t VERSION_UNKNOWN = 0;
    const int32_t VERSION_10 = 1;
    const int32_t VERSION_11 = 2;
    const int32_t VERSION_20 = 3;

    /*********************************************************************************
     * Http pocket parse status
     ********************************************************************************/
    const int32_t PARSE_NONE = 0;
    const int32_t PARSE_LINE = 1;
    const int32_t PARSE_HEADER = 2;
    const int32_t PARSE_CONTENT = 3;
    const int32_t PARSE_FINISHED = 4;
    const int32_t PARSE_FAILED = 5;

    class LIB_PUMP pocket
      : public header {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        pocket(int32_t pkt) noexcept
          : pkt_(pkt),
                version_(VERSION_UNKNOWN),
                body_(nullptr),
                parse_status_(PARSE_NONE) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~pocket() = default;

        /*********************************************************************************
         * Get pocket type
         ********************************************************************************/
        PUMP_INLINE int32_t get_type() const {
            return pkt_;
        }

        /*********************************************************************************
         * Parse
         * This parse http pocket, and return parsed size. If this return -1, it means
         * parsed error.
         ********************************************************************************/
        virtual int32_t parse(
            const block_t *b,
            int32_t size) = 0;

        /*********************************************************************************
         * Serialize
         * This serialize http pocket and return serialized size.
         ********************************************************************************/
        virtual int32_t serialize(std::string &buffer) const = 0;

        /*********************************************************************************
         * Set http content
         ********************************************************************************/
        PUMP_INLINE void set_body(body_sptr &b) {
            body_ = b;
        }

        /*********************************************************************************
         * Get http content
         ********************************************************************************/
        PUMP_INLINE const body_sptr get_content() const {
            return body_;
        }

        /*********************************************************************************
         * Set http version
         ********************************************************************************/
        PUMP_INLINE void set_http_version(int32_t version) {
            version_ = version;
        }

        /*********************************************************************************
         * Get http version
         ********************************************************************************/
        PUMP_INLINE int32_t get_http_version() const {
            return version_;
        }

        /*********************************************************************************
         * Get http version string
         ********************************************************************************/
        PUMP_INLINE std::string get_http_version_string() const {
            if (version_ == VERSION_10) {
                return "HTTP/1.0";
            } else if (version_ == VERSION_11) {
                return "HTTP/1.1";
            } else if (version_ == VERSION_20) {
                return "HTTP/2.0";
            }
            return "";
        }

        /*********************************************************************************
         * Check parse finished or not
         ********************************************************************************/
        PUMP_INLINE bool is_parse_finished() const {
            return parse_status_ == PARSE_FINISHED;
        }

      protected:
        // Http pocket type
        int32_t pkt_;

        // Http version
        int32_t version_;

        // Http body
        body_sptr body_;

        // Parse status
        int32_t parse_status_;
    };
    DEFINE_ALL_POINTER_TYPE(pocket);

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif