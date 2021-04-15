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

#ifndef pump_protocol_http_utils_h
#define pump_protocol_http_utils_h

#include "pump/utils.h"
#include "pump/transport/address.h"

namespace pump {
namespace protocol {
namespace http {

    #define HTTP_CR "\r\n"

    #define HTTP_CR_LEN 2

    #define HTTP_LINE_MAX_LEN 2048
    #define HTTP_LINE_MIN_LEN HTTP_CR_LEN

    #define HTTP_HEAD_VALUE_MAX_LEN (HTTP_LINE_MAX_LEN - 5)

    /*********************************************************************************
     * Find http line end position
     ********************************************************************************/
    LIB_PUMP const block_t* find_http_line_end(
        const block_t *src, 
        int32_t len);

    /*********************************************************************************
     * Decode url string
     ********************************************************************************/
    LIB_PUMP bool url_decode(
        const std::string &src, 
        std::string &des);

    /*********************************************************************************
     * Encode to url string
     ********************************************************************************/
    LIB_PUMP bool url_encode(
        const std::string &src, 
        std::string &des);

    /*********************************************************************************
     * Host to address
     ********************************************************************************/
    LIB_PUMP transport::address host_to_address(
        bool https, 
        const std::string &host);

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif