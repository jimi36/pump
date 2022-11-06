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

#include <pump/proto/http/packet.h>

namespace pump {
namespace proto {
namespace http {

typedef int32_t http_method;
const static http_method METHOD_UNKNOWN = 0;
const static http_method METHOD_GET = 1;
const static http_method METHOD_POST = 2;
const static http_method METHOD_HEAD = 3;
const static http_method METHOD_PUT = 4;
const static http_method METHOD_DELETE = 5;

class pump_lib request : public packet {
  public:
    /*********************************************************************************
     * Constructor
     * This construct a http request to serialize.
     ********************************************************************************/
    request(void *ctx = nullptr) pump_noexcept;
    request(void *ctx, const std::string &url) pump_noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~request() = default;

    /*********************************************************************************
     * Set request method
     ********************************************************************************/
    pump_inline void set_method(http_method method) pump_noexcept {
        method_ = method;
    }

    /*********************************************************************************
     * Get request method
     ********************************************************************************/
    pump_inline http_method get_method() const pump_noexcept {
        return method_;
    }

    /*********************************************************************************
     * Set request url
     ********************************************************************************/
    pump_inline void set_url(const std::string &url) {
        uri_.parse(url);
    }

    /*********************************************************************************
     * Get http uri
     ********************************************************************************/
    pump_inline const uri *get_uri() const pump_noexcept {
        return (const uri *)&uri_;
    }
    pump_inline uri *get_uri() pump_noexcept {
        return &uri_;
    }

    /*********************************************************************************
     * Parse
     * This parse http packet, and return parsed size.
     * If parsed error, return -1.
     ********************************************************************************/
    virtual int32_t parse(const char *b, int32_t size) override;

    /*********************************************************************************
     * Serialize
     * This will serialize http packet and return serialized size.
     ********************************************************************************/
    virtual int32_t serialize(std::string &buf) const override;

  private:
    /*********************************************************************************
     * Parse http start line
     ********************************************************************************/
    int32_t __parse_start_line(const char *b, int32_t size);

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
DEFINE_SMART_POINTERS(request);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
