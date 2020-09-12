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

#ifndef pump_protocol_websocket_utils_h
#define pump_protocol_websocket_utils_h

#include "pump/protocol/http/request.h"
#include "pump/protocol/http/response.h"

namespace pump {
namespace protocol {
    namespace websocket {

        /*********************************************************************************
         * Compute Sec-WebSocket-Key
         ********************************************************************************/
        std::string compute_sec_key();

        /*********************************************************************************
         * Compute Sec-WebSocket-Accept
         ********************************************************************************/
        std::string compute_sec_accept_key(const std::string &sec_key);

        /*********************************************************************************
         * Match websocket protocol
         ********************************************************************************/
        std::string match_protocol(const std::vector<std::string> &srcs,
                                   const std::string &des);

        /*********************************************************************************
         * Send http error response
         ********************************************************************************/
        void send_http_error_response(http::connection_ptr conn,
                                      int32 status_code,
                                      const std::string &reason);

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump

#endif