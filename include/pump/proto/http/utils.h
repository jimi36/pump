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

#include <pump/utils.h>

namespace pump {
namespace proto {
namespace http {

#define http_crlf "\r\n"

#define http_crlf_length 2

#define http_line_max_length 2048
#define http_line_min_length http_crlf_length

/*********************************************************************************
 * Find http line end position
 ********************************************************************************/
pump_lib const char *find_http_line_end(const char *src, int32_t len);

/*********************************************************************************
 * Decode url string
 ********************************************************************************/
pump_lib bool url_decode(const std::string &src, std::string &des);

/*********************************************************************************
 * Encode to url string
 ********************************************************************************/
pump_lib bool url_encode(const std::string &src, std::string &des);

/*********************************************************************************
 * Compute Sec-WebSocket-Key
 ********************************************************************************/
pump_lib std::string compute_sec_key();

/*********************************************************************************
 * Compute Sec-WebSocket-Accept
 ********************************************************************************/
pump_lib std::string compute_sec_accept_key(const std::string &sec_key);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif