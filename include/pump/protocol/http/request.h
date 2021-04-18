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

#ifndef pump_protocol_http_request_h
#define pump_protocol_http_request_h

#include "pump/protocol/http/pocket.h"

namespace pump {
namespace protocol {
namespace http {

    const static int32_t METHOD_UNKNOWN = 0;
    const static int32_t METHOD_GET = 1;
    const static int32_t METHOD_POST = 2;
    const static int32_t METHOD_HEAD = 3;
    const static int32_t METHOD_PUT = 4;
    const static int32_t METHOD_DELETE = 5;

    class request;
    DEFINE_ALL_POINTER_TYPE(request);

    class LIB_PUMP request 
      : public pocket {

      public:
        /*********************************************************************************
         * Constructor
         * This construct a http request to serialize.
         ********************************************************************************/
        request(void *ctx = nullptr) noexcept;
        request(
            const std::string &url,
            void *ctx = nullptr) noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~request() = default;

        /*********************************************************************************
         * Set request method
         ********************************************************************************/
        PUMP_INLINE void set_method(int32_t method) {
            method_ = method;
        }

        /*********************************************************************************
         * Get request method
         ********************************************************************************/
        PUMP_INLINE int32_t get_method() const {
            return method_;
        }

        /*********************************************************************************
         * Set request url
         ********************************************************************************/
        PUMP_INLINE void set_url(const std::string &url) {
            uri_.parse(url);
        }

        /*********************************************************************************
         * Get http uri
         ********************************************************************************/
        PUMP_INLINE const uri* get_uri() const {
            return (const uri*)&uri_;
        }
        PUMP_INLINE uri* get_uri() {
            return &uri_;
        }

        /*********************************************************************************
         * Get context
         ********************************************************************************/
        PUMP_INLINE void *get_context() const {
            return ctx_;
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
         * This will serialize http pocket and return serialized size.
         ********************************************************************************/
        virtual int32_t serialize(std::string &buf) const override;

      private:
        /*********************************************************************************
         * Parse http start line
         ********************************************************************************/
        int32_t __parse_start_line(
            const block_t *b, 
            int32_t size);

        /*********************************************************************************
         * Serialize http request line
         ********************************************************************************/
        int32_t __serialize_request_line(std::string &buffer) const;

      private:
        // Request context
        void *ctx_;
        // Request uri
        uri uri_;
        // Request method
        int32_t method_;
    };

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif