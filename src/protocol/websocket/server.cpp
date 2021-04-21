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

// Import std::find function
#include <algorithm>

#include "pump/protocol/websocket/utils.h"
#include "pump/protocol/websocket/server.h"

namespace pump {
namespace protocol {
namespace websocket {

    server::server(const transport::address &listen_address) noexcept 
      : sv_(nullptr) {
        acceptor_ = transport::tcp_acceptor::create(listen_address);
    }

    server::server(
        const transport::address &listen_address,
        const std::string &certfile,
        const std::string &keyfile) noexcept 
      : sv_(nullptr) {
        acceptor_ = transport::tls_acceptor::create_with_file(
                        certfile, 
                        keyfile, 
                        listen_address);
    }

    bool server::start(
        service *sv, 
        const server_callbacks &scbs) {
        PUMP_DEBUG_FAILED_RUN(
            sv == nullptr, 
            "websocket::server: start failed for service invalid",
            return false);
        sv_ = sv;

        PUMP_DEBUG_FAILED_RUN(
            !scbs.upgraded_cb,
            "websocket::server: start failed for callbacks invalid",
            return false);
        cbs_ = scbs;

        transport::acceptor_callbacks cbs;
        server_wptr wptr = shared_from_this();
        cbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
        cbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);
        if (acceptor_->start(sv, cbs) != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    void server::stop() {
        if (acceptor_ && acceptor_->is_started()) {
            acceptor_->stop();
        }
    }

    void server::on_accepted(
        server_wptr wptr, 
        transport::base_transport_sptr &transp) {
        auto svr = wptr.lock();
        if (svr) {
            service *sv = svr->sv_;
            if (svr->select_service_cb_) {
                sv = svr->select_service_cb_();
            }

            connection_sptr conn(new connection(sv, transp, false));
            {
                std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
                svr->conns_[conn.get()] = conn;
            }

            upgrade_callbacks ucbs;
            ucbs.pocket_cb = pump_bind(&server::on_upgrade_request, wptr, conn.get(), _1);
            ucbs.error_cb = pump_bind(&server::on_error, wptr, conn.get(), _1);
            if (!conn->start_upgrade(false, ucbs)) {
                std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
                svr->conns_.erase(conn.get());
            }
        }
    }

    void server::on_stopped(server_wptr wptr) {
        auto svr = wptr.lock();
        if (svr) {
            // Stop all upgrading connections
            svr->__stop_all_upgrading_conns();

            if (svr->cbs_.error_cb) {
                svr->cbs_.error_cb("websocket server stopped");
            }
        }
    }

    void server::on_upgrade_request(
        server_wptr wptr,
        connection *conn,
        http::pocket_sptr pk) {
        auto svr = wptr.lock();
        if (svr) {
            connection_sptr conn_locker;
            {
                std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
                // Try locking connection instance
                auto it = svr->conns_.find(conn);
                if (it == svr->conns_.end()) {
                    return;
                }
                conn_locker = it->second;
                // Remove connection from connection list
                svr->conns_.erase(it);
            }

            auto req = std::static_pointer_cast<http::request>(pk);
            if (!svr->__handle_upgrade_request(conn, req.get())) {
                conn->stop();
                return;
            }

            if (svr->cbs_.upgraded_cb) {
                svr->cbs_.upgraded_cb(req->get_uri()->get_path(), conn_locker);
            }
        }
    }

    void server::on_error(
        server_wptr wptr,
        connection *conn,
        const std::string &msg) {
        auto svr = wptr.lock();
        if (svr) {
            std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
            auto it = svr->conns_.find(conn);
            if (it != svr->conns_.end()) {
                conn->stop();
                svr->conns_.erase(it);
            }
        }
    }

    bool server::__handle_upgrade_request(
        connection *conn,
        http::request *req) {
        if (req->get_method() != http::METHOD_GET) {
            send_http_error_response(conn, 404, "");
            return false;
        }

        auto version = req->get_http_version();
        if (version != http::VERSION_11) {
            send_http_error_response(conn, 404, "");
            return false;
        }

        std::string upgrade;
        if (!req->get_head("Upgrade", upgrade) || upgrade != "websocket") {
            send_http_error_response(
                conn, 400, "Upgrade header is not found or invalid");
            return false;
        }

        std::vector<std::string> connection;
        if (!req->get_head("Connection", connection) ||
            std::find(connection.begin(), connection.end(), "Upgrade") == connection.end()) {
            send_http_error_response(
                conn, 400, "Connection header is not found or invalid");
            return false;
        }

        std::string sec_version;
        if (!req->get_head("Sec-WebSocket-Version", sec_version) || sec_version != "13") {
            send_http_error_response(
                conn, 400, "Sec-WebSocket-Version header is not found or invalid");
            return false;
        }

        std::string sec_key;
        if (!req->get_head("Sec-WebSocket-Key", sec_key)) {
            send_http_error_response(
                conn, 400, "Sec-WebSocket-Key header is not found or invalid");
            return false;
        }

        if (cbs_.check_request_cb) {
            if (!cbs_.check_request_cb(req)) {
                send_http_error_response(conn, 400, "Request is invalid");
                return false;
            }
        }

        http::response resp;
        resp.set_status_code(101);
        resp.set_http_version(version);
        resp.set_head("Upgrade", "websocket");
        resp.set_head("Connection", "Upgrade");
        resp.set_head("Sec-WebSocket-Accept", compute_sec_accept_key(sec_key));

        std::vector<std::string> protocs;
        req->get_head("Sec-WebSocket-Protocol", protocs);
        for (int32_t i = 0; i < (int32_t)protocs.size(); i++) {
            resp.set_head("Sec-WebSocket-Protocol", protocs[i]);
        }

        std::string data;
        resp.serialize(data);
        return conn->send_raw(data.c_str(), (int32_t)data.size());
    }

    void server::__stop_all_upgrading_conns() {
        std::lock_guard<std::mutex> lock(conn_mx_);
        for (auto &p : conns_) {
            p.second->stop();
        }
        conns_.clear();
    }

}  // namespace websocket
}  // namespace protocol
}  // namespace pump
