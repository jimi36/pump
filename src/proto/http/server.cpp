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

server::server() pump_noexcept
  : sv_(nullptr) {
}

bool server::start(
    service *sv,
    const address &listen_address,
    const server_callbacks &cbs) {
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return false;
    }

    if (!cbs.request_cb ||
        !cbs.stopped_cb) {
        pump_warn_log("callbacks invalid");
        return false;
    }

    if (acceptor_) {
        pump_debug_log("server's acceptor alread exists");
        return false;
    }

    sv_ = sv;
    cbs_ = cbs;

    acceptor_callbacks acbs;
    server_wptr svr = shared_from_this();
    acbs.stopped_cb = pump_bind(&server::on_stopped, svr);
    acbs.accepted_cb = pump_bind(&server::on_accepted, svr, _1);

    auto acceptor = tcp_acceptor::create(listen_address);
    if (acceptor->start(sv, acbs) != error_none) {
        pump_debug_log("start tcp acceptor failed");
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
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return false;
    }

    if (!cbs.request_cb || !cbs.stopped_cb) {
        pump_debug_log("callbacks invalid");
        return false;
    }

    if (!acceptor_) {
        pump_debug_log("server's acceptor already exists");
        return false;
    }

    sv_ = sv;
    cbs_ = cbs;

    acceptor_callbacks acbs;
    server_wptr wptr = shared_from_this();
    acbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
    acbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

    auto acceptor = tls_acceptor::create(xcred, listen_address, 1000);
    if (acceptor->start(sv, acbs) != error_none) {
        pump_debug_log("start tls acceptor failed");
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

void server::on_accepted(
    server_wptr svr,
    base_transport_sptr &transp) {
    auto svr_locker = svr.lock();
    if (svr_locker) {
        connection_sptr conn(new connection(true, transp));
        do {
            std::unique_lock<std::mutex> lock(svr_locker->conn_mx_);
            svr_locker->conns_[conn.get()] = conn;
        } while (false);

        http_callbacks cbs;
        cbs.error_cb = pump_bind(&server::on_http_error, svr, conn, _1);
        cbs.packet_cb = pump_bind(&server::on_http_request, svr, conn, _1);
        if (!conn->start_http(svr_locker->sv_, cbs)) {
            pump_debug_log("start http connection failed");
            std::unique_lock<std::mutex> lock(svr_locker->conn_mx_);
            svr_locker->conns_.erase(conn.get());
        }
    }
}

void server::on_stopped(server_wptr svr) {
    auto svr_locker = svr.lock();
    if (svr_locker) {
        do {
            std::unique_lock<std::mutex> lock(svr_locker->conn_mx_);
            auto beg = svr_locker->conns_.begin();
            auto end = svr_locker->conns_.end();
            for (auto it = beg; it != end; it++) {
                it->second->stop();
            }
        } while (false);

        svr_locker->cbs_.stopped_cb();
    }
}

void server::on_http_request(
    server_wptr svr,
    connection_wptr conn,
    packet_sptr &pk) {
    auto svr_locker = svr.lock();
    if (svr_locker) {
        auto conn_locker = conn.lock();
        if (conn_locker) {
            svr_locker->cbs_.request_cb(conn, std::static_pointer_cast<request>(pk));
            if (conn_locker->is_upgraded()) {
                pump_debug_log("http connection upgrade to websocket");
                std::unique_lock<std::mutex> lock(svr_locker->conn_mx_);
                svr_locker->conns_.erase(conn_locker.get());
            } else {
                pump_debug_log("read next http request");
                if (!conn_locker->__async_read_http_packet()) {
                    // Stop http connection.
                    conn_locker->stop();
                    // Delete http connection.
                    std::unique_lock<std::mutex> lock(svr_locker->conn_mx_);
                    svr_locker->conns_.erase(conn_locker.get());
                }
            }
        }
    }
}

void server::on_http_error(
    server_wptr svr,
    connection_wptr conn,
    const std::string &msg) {
    auto conn_locker = conn.lock();
    if (conn_locker) {
        pump_debug_log("http connection error %s", msg.c_str());
        // Stop http connection.
        conn_locker->stop();
        // Delete http connection.
        auto svr_locker = svr.lock();
        if (svr_locker) {
            std::unique_lock<std::mutex> w_lock(svr_locker->conn_mx_);
            svr_locker->conns_.erase(conn_locker.get());
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
