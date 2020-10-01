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

        server::server() noexcept : sv_(nullptr) {
        }

        bool server::start(service_ptr sv,
                           const transport::address &listen_address,
                           const std::map<std::string, std::string> &local_headers) {
            if (acceptor_)
                return false;

            if (sv == nullptr)
                return false;

            sv_ = sv;

            local_headers_ = local_headers;

            transport::acceptor_callbacks cbs;
            server_wptr wptr = shared_from_this();
            cbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
            cbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

            acceptor_ = transport::tcp_acceptor::create_instance(listen_address);
            if (acceptor_->start(sv, cbs) != transport::ERROR_OK) {
                acceptor_.reset();
                return false;
            }

            return true;
        }

        bool server::start(service_ptr sv,
                           const std::string &crtfile,
                           const std::string &keyfile,
                           const transport::address &listen_address,
                           const std::map<std::string, std::string> &local_headers) {
            if (acceptor_)
                return false;

            if (sv == nullptr)
                return false;

            sv_ = sv;

            local_headers_ = local_headers;

            transport::acceptor_callbacks cbs;
            server_wptr wptr = shared_from_this();
            cbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
            cbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

            acceptor_ = transport::tls_acceptor::create_instance_with_file(
                crtfile, keyfile, listen_address);
            if (acceptor_->start(sv, cbs) != transport::ERROR_OK) {
                acceptor_.reset();
                return false;
            }

            return true;
        }

        void server::stop() {
            if (acceptor_ && acceptor_->is_started())
                acceptor_->stop();
        }

        void server::on_accepted(server_wptr wptr,
                                 transport::base_transport_sptr &transp) {
            PUMP_LOCK_WPOINTER(svr, wptr);
            if (svr == nullptr)
                return;

            service_ptr sv = nullptr;
            if (svr->select_service_cb_)
                sv = svr->select_service_cb_();
            if (sv == nullptr)
                sv = svr->sv_;

            http::connection_sptr conn(new http::connection(true, transp));
            {
                std::unique_lock<std::mutex> w_lock(svr->http_conn_mx_);
                svr->http_conns_[conn.get()] = conn;
            }

            http::http_callbacks cbs;
            cbs.pocket_cb = pump_bind(&server::on_upgrade_request, wptr, conn, _1);
            cbs.error_cb = pump_bind(&server::on_upgrade_error, wptr, conn, _1);
            if (!conn->start(sv, cbs)) {
                std::unique_lock<std::mutex> w_lock(svr->http_conn_mx_);
                svr->http_conns_.erase(conn.get());
            }
        }

        void server::on_stopped(server_wptr wptr) {
            PUMP_LOCK_WPOINTER(svr, wptr);
            if (svr == nullptr)
                return;

            svr->__stop_all_upgrading_conns();
        }

        void server::on_upgrade_request(server_wptr wptr,
                                        http::connection_wptr wptr_http_conn,
                                        http::pocket_sptr &&pk) {
            PUMP_LOCK_WPOINTER(http_conn, wptr_http_conn);
            if (http_conn == nullptr)
                return;

            PUMP_LOCK_WPOINTER(svr, wptr);
            if (svr == nullptr) {
                http_conn->stop();
                return;
            }

            auto req = (http::c_request_ptr)pk.get();
            if (!svr->__handle_upgrade_request(http_conn, req)) {
                http_conn->stop();
                return;
            }

            connection_sptr conn(new connection(false));
            if (!conn->upgrade(http_conn_locker)) {
                http_conn->stop();
                return;
            }

            svr->router_.route(req->get_uri()->get_path(), conn);
        }

        void server::on_upgrade_error(server_wptr wptr,
                                      http::connection_wptr wptr_http_conn,
                                      const std::string &msg) {
            PUMP_LOCK_WPOINTER(http_conn, wptr_http_conn);
            if (http_conn == nullptr)
                return;

            PUMP_LOCK_WPOINTER(svr, wptr);
            if (svr == nullptr)
                return;

            std::unique_lock<std::mutex> w_lock(svr->http_conn_mx_);
            svr->http_conns_.erase(http_conn);
        }

        bool server::__handle_upgrade_request(http::connection_ptr conn,
                                              http::c_request_ptr req) {
            if (req->get_method() != http::METHOD_GET) {
                send_http_error_response(conn, 404, "");
                return false;
            }

            auto header = req->get_header();
            auto version = req->get_http_version();
            if (req->get_method() != http::METHOD_GET || version != http::VERSION_11) {
                send_http_error_response(conn, 404, "");
                return false;
            }

            auto path = req->get_uri()->get_path();
            if (!router_.has_route(path)) {
                send_http_error_response(conn, 404, "");
                return false;
            }

            std::string local_host = __get_local_header("Host");
            if (!local_host.empty()) {
                std::string host;
                if (!header->get("Host", host) || host != local_host) {
                    send_http_error_response(conn, 403, "");
                    return false;
                }
            }

            std::string local_origin = __get_local_header("Origin");
            if (!local_origin.empty()) {
                std::string origin;
                if (!header->get("Origin", origin) || origin != local_origin) {
                    send_http_error_response(conn, 403, "");
                    return false;
                }
            }

            std::string upgrade;
            if (!header->get("Upgrade", upgrade) || upgrade != "websocket") {
                send_http_error_response(
                    conn, 400, "Upgrade header is not found or invalid");
                return false;
            }

            std::vector<std::string> connection;
            if (!header->get("Connection", connection) ||
                std::find(connection.begin(), connection.end(), "Upgrade") ==
                    connection.end()) {
                send_http_error_response(
                    conn, 400, "Connection header is not found or invalid");
                return false;
            }

            std::string sec_version;
            if (!header->get("Sec-WebSocket-Version", sec_version) ||
                sec_version != "13") {
                send_http_error_response(
                    conn, 400, "Sec-WebSocket-Version header is not found or invalid");
                return false;
            }

            std::string sec_key;
            if (!header->get("Sec-WebSocket-Key", sec_key)) {
                send_http_error_response(
                    conn, 400, "Sec-WebSocket-Key header is not found or invalid");
                return false;
            }

            std::vector<std::string> protocs;
            header->get("Sec-WebSocket-Protocol", protocs);
            std::string protocol =
                match_protocol(protocs, __get_local_header("Sec-WebSocket-Protocol"));

            http::response resp;
            resp.set_status_code(101);
            resp.set_http_version(version);

            http::header_ptr resp_header = resp.get_header();
            resp_header->set("Upgrade", "websocket");
            resp_header->set("Connection", "Upgrade");
            resp_header->set("Sec-WebSocket-Accept", compute_sec_accept_key(sec_key));
            if (!protocol.empty())
                resp_header->set("Sec-WebSocket-Protocol", protocol);

            return conn->send(&resp);
        }

        void server::__stop_all_upgrading_conns() {
            std::lock_guard<std::mutex> lock(http_conn_mx_);
            for (auto p : http_conns_) {
                p.second->stop();
            }
            http_conns_.clear();
        }

        const std::string &server::__get_local_header(const std::string &name) const {
            const static std::string EMPTY("");
            auto it = local_headers_.find(name);
            if (it != local_headers_.end())
                return it->second;
            return EMPTY;
        }

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump
