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

#include "pump/proto/http/server.h"

namespace pump {
namespace proto {
namespace http {

using transport::acceptor_callbacks;
using transport::error_none;
using transport::tcp_acceptor;
using transport::tls_acceptor;

server::server() noexcept :
    sv_(nullptr) {}

server::~server() {}

bool server::start(
    service *sv,
    const address &listen_address,
    const server_callbacks &cbs) {
    if (acceptor_) {
        pump_warn_log("acceptor alread exists");
        return false;
    }

    if (sv == nullptr) {
        pump_warn_log("service invalid");
        return false;
    }

    if (!cbs.request_cb || !cbs.stopped_cb) {
        pump_warn_log("server callbacks invalid");
        return false;
    }

    sv_ = sv;
    cbs_ = cbs;

    acceptor_callbacks acbs;
    server_wptr wptr = shared_from_this();
    acbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
    acbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

    auto acceptor = tcp_acceptor::create(listen_address);
    if (acceptor->start(sv, acbs) != error_none) {
        pump_warn_log("start tcp acceptor failed");
        return false;
    }
    acceptor_ = acceptor;

    return true;
}

bool server::start(
    service *sv,
    tls_credentials xcred,
    const address &listen_address,
    const server_callbacks &cbs) {
    if (!acceptor_) {
        pump_warn_log("acceptor alread exists");
        return false;
    }

    if (sv == nullptr) {
        pump_warn_log("service invalid");
        return false;
    }
    sv_ = sv;

    if (!cbs.request_cb || !cbs.stopped_cb) {
        pump_warn_log("server callbacks invalid");
        return false;
    }
    cbs_ = cbs;

    acceptor_callbacks acbs;
    server_wptr wptr = shared_from_this();
    acbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
    acbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

    auto acceptor = tls_acceptor::create(xcred, listen_address, 1000);
    if (acceptor->start(sv, acbs) != error_none) {
        pump_warn_log("start tls acceptor failed");
        return false;
    }
    acceptor_ = acceptor;

    return true;
}

void server::stop() {
    if (acceptor_) {
        acceptor_->stop();
    }
}

void server::on_accepted(server_wptr wptr, base_transport_sptr &transp) {
    auto svr = wptr.lock();
    if (svr) {
        connection_sptr conn(new connection(true, transp));
        do {
            std::unique_lock<std::mutex> lock(svr->conn_mx_);
            svr->conns_[conn.get()] = conn;
        } while (false);

        http_callbacks cbs;
        cbs.error_cb = pump_bind(&server::on_http_error, wptr, conn, _1);
        cbs.packet_cb = pump_bind(&server::on_http_request, wptr, conn, _1);
        if (!conn->start_http(svr->sv_, cbs)) {
            pump_warn_log("start http connection failed");
            std::unique_lock<std::mutex> lock(svr->conn_mx_);
            svr->conns_.erase(conn.get());
        }
    }
}

void server::on_stopped(server_wptr wptr) {
    auto svr = wptr.lock();
    if (svr) {
        do {
            std::unique_lock<std::mutex> lock(svr->conn_mx_);
            auto beg = svr->conns_.begin();
            auto end = svr->conns_.end();
            for (auto it = beg; it != end; it++) {
                it->second->stop();
            }
        } while (false);

        svr->cbs_.stopped_cb();
    }
}

void server::on_http_request(
    server_wptr wptr,
    connection_wptr wconn,
    packet_sptr &pk) {
    auto svr = wptr.lock();
    if (svr) {
        auto conn = wconn.lock();
        if (conn) {
            svr->cbs_.request_cb(wconn, std::static_pointer_cast<request>(pk));
            if (conn->is_upgraded()) {
                pump_debug_log("http connection upgrade to websocket");
                std::unique_lock<std::mutex> lock(svr->conn_mx_);
                svr->conns_.erase(conn.get());
            } else {
                pump_warn_log("try to read next http request failed");
                if (!conn->__read_next_http_packet()) {
                    // Stop http connection.
                    conn->stop();
                    // Delete http connection.
                    std::unique_lock<std::mutex> lock(svr->conn_mx_);
                    svr->conns_.erase(conn.get());
                }
            }
        }
    }
}

void server::on_http_error(
    server_wptr wptr,
    connection_wptr wconn,
    const std::string &msg) {
    auto conn = wconn.lock();
    if (conn) {
        pump_debug_log("connection of http server %s", msg.c_str());
        // Stop http connection.
        conn->stop();
        // Delete http connection.
        auto svr = wptr.lock();
        if (svr) {
            std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
            svr->conns_.erase(conn.get());
        }
    }
}

bool __send_simple_response(connection *conn, int32_t status_code) {
    http::response rsp;
    rsp.set_http_version(http::VERSION_11);
    rsp.set_status_code(status_code);
    return conn->send(&rsp);
}

bool upgrade_to_websocket(connection *conn, request_sptr &req) {
    if (req->get_method() != http::METHOD_GET) {
        __send_simple_response(conn, 404);
        return false;
    }

    auto version = req->get_http_version();
    if (version != http::VERSION_11) {
        __send_simple_response(conn, 404);
        return false;
    }

    std::string upgrade;
    if (!req->get_head("Upgrade", upgrade) || upgrade != "websocket") {
        __send_simple_response(conn, 400);
        return false;
    }

    std::vector<std::string> connection;
    if (!req->get_head("Connection", connection) ||
        std::find(connection.begin(), connection.end(), "Upgrade") == connection.end()) {
        __send_simple_response(conn, 400);
        return false;
    }

    std::string sec_version;
    if (!req->get_head("Sec-WebSocket-Version", sec_version) ||
        sec_version != "13") {
        __send_simple_response(conn, 400);
        return false;
    }

    std::string sec_key;
    if (!req->get_head("Sec-WebSocket-Key", sec_key)) {
        __send_simple_response(conn, 400);
        return false;
    }

    http::response rsp;
    rsp.set_status_code(101);
    rsp.set_http_version(version);
    rsp.set_head("Upgrade", "websocket");
    rsp.set_head("Connection", "Upgrade");
    rsp.set_head("Sec-WebSocket-Accept", compute_sec_accept_key(sec_key));

    std::vector<std::string> protocs;
    req->get_head("Sec-WebSocket-proto", protocs);
    for (int32_t i = 0; i < (int32_t)protocs.size(); i++) {
        rsp.set_head("Sec-WebSocket-proto", protocs[i]);
    }

    return conn->send(&rsp);
}

}  // namespace http
}  // namespace proto
}  // namespace pump
