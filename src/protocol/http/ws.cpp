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

#include <algorithm>

#include "pump/protocol/http/ws.h"
#include "pump/protocol/http/ws_frame.h"

namespace pump {
namespace protocol {
namespace http {

    bool send_upgrade_websocket_request(
        connection_sptr &conn, 
        const std::string &url, 
        std::map<std::string, std::string> &headers) {
        // Create upgrade request.
        request req(url);
        req.set_http_version(http::VERSION_11);
        req.set_method(http::METHOD_GET);
        for (auto &h : headers) {
            req.set_head(h.first, h.second);
        }
        auto u = req.get_uri();
        if (!req.has_head("Host")) {
            req.set_unique_head("Host", u->get_host());
        }
        req.set_unique_head("Connection", "Upgrade");
        req.set_unique_head("Upgrade", "websocket");
        req.set_unique_head("Sec-WebSocket-Version", "13");
        req.set_unique_head("Sec-WebSocket-Key", compute_sec_key());

        std::string data;
        req.serialize(data);
        return conn->send(data.c_str(), (int32_t)data.size());
    }

    bool handle_upgrade_websocket_request(
        connection_sptr &conn, 
        request_sptr &req) {
        if (req->get_method() != http::METHOD_GET) {
            send_http_simple_response(conn, 404, "");
            return false;
        }

        auto version = req->get_http_version();
        if (version != http::VERSION_11) {
            send_http_simple_response(conn, 404, "");
            return false;
        }

        std::string upgrade;
        if (!req->get_head("Upgrade", upgrade) || upgrade != "websocket") {
            send_http_simple_response(
                conn, 400, "Upgrade header is not found or invalid");
            return false;
        }

        std::vector<std::string> connection;
        if (!req->get_head("Connection", connection) ||
            std::find(connection.begin(), connection.end(), "Upgrade") == connection.end()) {
            send_http_simple_response(
                conn, 400, "Connection header is not found or invalid");
            return false;
        }

        std::string sec_version;
        if (!req->get_head("Sec-WebSocket-Version", sec_version) || sec_version != "13") {
            send_http_simple_response(
                conn, 400, "Sec-WebSocket-Version header is not found or invalid");
            return false;
        }

        std::string sec_key;
        if (!req->get_head("Sec-WebSocket-Key", sec_key)) {
            send_http_simple_response(
                conn, 400, "Sec-WebSocket-Key header is not found or invalid");
            return false;
        }

        http::response rsp;
        rsp.set_status_code(101);
        rsp.set_http_version(version);
        rsp.set_head("Upgrade", "websocket");
        rsp.set_head("Connection", "Upgrade");
        rsp.set_head("Sec-WebSocket-Accept", compute_sec_accept_key(sec_key));

        std::vector<std::string> protocs;
        req->get_head("Sec-WebSocket-Protocol", protocs);
        for (int32_t i = 0; i < (int32_t)protocs.size(); i++) {
            rsp.set_head("Sec-WebSocket-Protocol", protocs[i]);
        }

        std::string data;
        rsp.serialize(data);
        return conn->send(data.c_str(), (int32_t)data.size());
    }

    bool handle_upgrade_websocket_response(
        connection_sptr &conn, 
        response_sptr &rsp) {
        if (rsp->get_status_code() != 101 ||
            rsp->get_http_version() != http::VERSION_11) {
            return false;
        }

        std::string upgrade;
        if (!rsp->get_head("Upgrade", upgrade) || upgrade != "websocket") {
            return false;
        }

        std::vector<std::string> connection;
        if (!rsp->get_head("Connection", connection) ||
            std::find(connection.begin(), connection.end(), "Upgrade") == connection.end()) {
            return false;
        }

        std::string sec_accept;
        if (!rsp->get_head("Sec-WebSocket-Accept", sec_accept)) {
            return false;
        }

        return true;
    }

    bool send_websocket_ping(connection *conn) {
        ws_frame_header hdr;
        init_ws_frame_header(&hdr, 1, WS_FOT_PING, 0, 0, 0);
        uint32_t hdr_size = get_ws_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_ws_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG("websocket: encode ping frame header failed");
            return false;
        }

        if (!conn->send(buffer.c_str(), (int32_t)buffer.size())) {
            PUMP_DEBUG_LOG("websocket: send ping frame failed");
            return false;
        }

        return true;
    }

    bool send_websocket_pong(connection *conn) {
        ws_frame_header hdr;
        init_ws_frame_header(&hdr, 1, WS_FOT_PONG, 0, 0, 0);
        int32_t hdr_size = get_ws_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_ws_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG("websocket: encode pong frame header failed");
            return false;
        }

        if (!conn->send(buffer.c_str(), (int32_t)buffer.size())) {
            PUMP_DEBUG_LOG("websocket: send pong frame failed");
            return false;
        }

        return true;
    }

    bool send_wbesocket_close(connection *conn) {
        ws_frame_header hdr;
        init_ws_frame_header(&hdr, 1, WS_FOT_CLOSE, 0, 0, 0);
        int32_t hdr_size = get_ws_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_ws_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG("websocket: encode close frame header failed");
            return false;
        }

        if (!conn->send(buffer.c_str(), (int32_t)buffer.size())) {
            PUMP_DEBUG_LOG("websocket: send close frame failed");
            return false;
        }

        return true;
    }

}
}
}