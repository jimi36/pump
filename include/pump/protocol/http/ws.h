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

#ifndef pump_protocol_http_ws_h
#define pump_protocol_http_ws_h

#include "pump/protocol/http/request.h"
#include "pump/protocol/http/response.h"
#include "pump/protocol/http/connection.h"

namespace pump {
namespace protocol {
namespace http {

    bool send_upgrade_websocket_request(
        connection_sptr &conn, 
        const std::string &url, 
        std::map<std::string, std::string> &headers);

    bool handle_upgrade_websocket_request(
        connection_sptr &conn, 
        request_sptr &req);

    bool handle_upgrade_websocket_response(
        connection_sptr &conn, 
        response_sptr &rsp);

    bool send_websocket_ping(connection *conn);

    bool send_websocket_pong(connection *conn);

    bool send_wbesocket_close(connection *conn);

}
}
}

#endif