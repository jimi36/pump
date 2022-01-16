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

#ifndef pump_proto_http_utils_h
#define pump_proto_http_utils_h

#include "pump/utils.h"

namespace pump {
namespace proto {
namespace http {

    #define HTTP_CRLF "\r\n"

    #define HTTP_CRLF_LEN 2

    #define HTTP_LINE_MAX_LEN 2048
    #define HTTP_LINE_MIN_LEN HTTP_CRLF_LEN

    #define HTTP_HEAD_VALUE_MAX_LEN (HTTP_LINE_MAX_LEN - 5)

    /*********************************************************************************
     * Find http line end position
     ********************************************************************************/
    LIB_PUMP const block_t* find_http_line_end(const block_t *src, int32_t len);

    /*********************************************************************************
     * Decode url string
     ********************************************************************************/
    LIB_PUMP bool url_decode(const std::string &src, std::string &des);

    /*********************************************************************************
     * Encode to url string
     ********************************************************************************/
    LIB_PUMP bool url_encode(const std::string &src, std::string &des);

    /*********************************************************************************
     * Compute Sec-WebSocket-Key
     ********************************************************************************/
    LIB_PUMP std::string compute_sec_key();

    /*********************************************************************************
     * Compute Sec-WebSocket-Accept
     ********************************************************************************/
    LIB_PUMP std::string compute_sec_accept_key(const std::string &sec_key);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif