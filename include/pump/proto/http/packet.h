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

#ifndef pump_proto_http_packet_h
#define pump_proto_http_packet_h

#include "pump/proto/http/uri.h"
#include "pump/proto/http/body.h"
#include "pump/proto/http/header.h"

namespace pump {
namespace proto {
namespace http {

/*********************************************************************************
 * Http packet type
 ********************************************************************************/
typedef int32_t packet_type;
const packet_type PK_UNKNOWN = 0;
const packet_type PK_REQUEST = 1;
const packet_type PK_RESPONSE = 2;

/*********************************************************************************
 * Http version
 ********************************************************************************/
typedef int32_t http_version;
const http_version VERSION_UNKNOWN = 0;
const http_version VERSION_10 = 1;
const http_version VERSION_11 = 2;
const http_version VERSION_20 = 3;

/*********************************************************************************
 * Http packet parse status
 ********************************************************************************/
const int32_t PARSE_NONE = 0;
const int32_t PARSE_LINE = 1;
const int32_t PARSE_HEADER = 2;
const int32_t PARSE_BODY = 3;
const int32_t PARSE_FINISHED = 4;
const int32_t PARSE_FAILED = 5;

class LIB_PUMP packet : public header {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    packet(void *ctx, int32_t pkt) noexcept :
        ctx_(ctx),
        pkt_(pkt),
        version_(VERSION_UNKNOWN),
        body_(nullptr),
        parse_status_(PARSE_NONE) {}

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~packet() = default;

    /*********************************************************************************
     * Get context
     ********************************************************************************/
    PUMP_INLINE void *get_context() const {
        return ctx_;
    }

    /*********************************************************************************
     * Set context
     ********************************************************************************/
    PUMP_INLINE void set_context(void *ctx) {
        ctx_ = ctx;
    }

    /*********************************************************************************
     * Get packet type
     ********************************************************************************/
    PUMP_INLINE int32_t get_type() const {
        return pkt_;
    }

    /*********************************************************************************
     * Parse
     * This parse http packet, and return parsed size. If error return -1.
     ********************************************************************************/
    virtual int32_t parse(const block_t *b, int32_t size) = 0;

    /*********************************************************************************
     * Serialize
     * This serialize http packet and return serialized size.
     ********************************************************************************/
    virtual int32_t serialize(std::string &buffer) const = 0;

    /*********************************************************************************
     * Set http body
     ********************************************************************************/
    PUMP_INLINE void set_body(body_sptr &b) {
        body_ = b;
    }

    /*********************************************************************************
     * Get http body
     ********************************************************************************/
    PUMP_INLINE const body_sptr get_body() const {
        return body_;
    }

    /*********************************************************************************
     * Set http version
     ********************************************************************************/
    PUMP_INLINE void set_http_version(http_version version) {
        version_ = version;
    }

    /*********************************************************************************
     * Get http version
     ********************************************************************************/
    PUMP_INLINE http_version get_http_version() const {
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
    // Http packet context
    void *ctx_;

    // Http packet type
    packet_type pkt_;

    // Http version
    http_version version_;

    // Http body
    body_sptr body_;

    // Parse status
    int32_t parse_status_;
};
DEFINE_SMART_POINTER_TYPE(packet);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
