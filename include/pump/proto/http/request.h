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

#ifndef pump_proto_http_request_h
#define pump_proto_http_request_h

#include "pump/proto/http/packet.h"

namespace pump {
namespace proto {
namespace http {

    typedef int32_t http_method;
    const static http_method METHOD_UNKNOWN = 0;
    const static http_method METHOD_GET     = 1;
    const static http_method METHOD_POST    = 2;
    const static http_method METHOD_HEAD    = 3;
    const static http_method METHOD_PUT     = 4;
    const static http_method METHOD_DELETE  = 5;

    class LIB_PUMP request 
      : public packet {

      public:
        /*********************************************************************************
         * Constructor
         * This construct a http request to serialize.
         ********************************************************************************/
        request(void *ctx = nullptr) noexcept;
        request(void *ctx, const std::string &url) noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~request() = default;

        /*********************************************************************************
         * Set request method
         ********************************************************************************/
        PUMP_INLINE void set_method(http_method method) {
            method_ = method;
        }

        /*********************************************************************************
         * Get request method
         ********************************************************************************/
        PUMP_INLINE http_method get_method() const {
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
         * Parse
         * This parse http packet, and return parsed size. 
         * If parsed error, return -1.
         ********************************************************************************/
        virtual int32_t parse(const block_t *b, int32_t size) override;

        /*********************************************************************************
         * Serialize
         * This will serialize http packet and return serialized size.
         ********************************************************************************/
        virtual int32_t serialize(std::string &buf) const override;

      private:
        /*********************************************************************************
         * Parse http start line
         ********************************************************************************/
        int32_t __parse_start_line(const block_t *b, int32_t size);

        /*********************************************************************************
         * Serialize http request line
         ********************************************************************************/
        int32_t __serialize_request_line(std::string &buffer) const;

      private:
        // Request uri
        uri uri_;
        // Request method
        http_method method_;
    };
    DEFINE_ALL_POINTER_TYPE(request);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
