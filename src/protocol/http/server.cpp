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

#include "pump/protocol/http/server.h"

namespace pump {
namespace protocol {
namespace http {

    server::server() noexcept
      : sv_(nullptr) {
    }

    server::~server() {
    }

    bool server::start(
        service *sv,
        const transport::address &listen_address,
        const server_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !!acceptor_,
            "http::server: start failed for acceptor alread exists",
            return false);

        PUMP_DEBUG_FAILED(
            sv == nullptr,
            "http::server: start failed for service invalid",
            return false);
        sv_ = sv;

        // Check callbacks
        PUMP_DEBUG_FAILED(
            !cbs.request_cb || !cbs.stopped_cb,
            "http::server: start failed for callbacks invalid",
            return false);
        cbs_ = cbs;

        transport::acceptor_callbacks acbs;
        server_wptr wptr = shared_from_this();
        acbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
        acbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

        auto acceptor = transport::tcp_acceptor::create(listen_address);
        if (acceptor->start(sv, acbs) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("http::server: start failed for starting tcp acceptor failed");
            return false;
        }
        acceptor_ = acceptor;

        return true;
    }

    bool server::start(
        service *sv,
        transport::tls_credentials xcred,
        const transport::address &listen_address,
        const server_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !!acceptor_,
            "http::server: start failed for acceptor already exists",
            return false);

        PUMP_DEBUG_FAILED(
            sv == nullptr,
            "http::server: start failed for service invalid",
            PUMP_ABORT());
        sv_ = sv;

        // Check callbacks
        PUMP_DEBUG_FAILED(
            !cbs.request_cb || !cbs.stopped_cb,
            "http::server: start failed for callbacks invalid",
            PUMP_ABORT());
        cbs_ = cbs;

        transport::acceptor_callbacks acbs;
        server_wptr wptr = shared_from_this();
        acbs.stopped_cb = pump_bind(&server::on_stopped, wptr);
        acbs.accepted_cb = pump_bind(&server::on_accepted, wptr, _1);

        auto acceptor = transport::tls_acceptor::create(
                            xcred, 
                            listen_address, 
                            1000);
        if (acceptor->start(sv, acbs) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("http::server: start failed for starting tls acceptor failed");
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
        server_wptr wptr,
        transport::base_transport_sptr &transp) {
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
                std::unique_lock<std::mutex> lock(svr->conn_mx_);
                svr->conns_.erase(conn.get());
            }

            //PUMP_DEBUG_CHECK(conn->read_again());
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
                    std::unique_lock<std::mutex> lock(svr->conn_mx_);
                    svr->conns_.erase(conn.get());
                } else {
                    if (!conn->read_again()) {
                        conn->stop();
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
            auto svr = wptr.lock();
            if (svr) {
                std::unique_lock<std::mutex> w_lock(svr->conn_mx_);
                svr->conns_.erase(conn.get());
            }

            conn->stop();
        }
  
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump