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

#include "pump/protocol/http/client.h"
#include "pump/transport/tcp_dialer.h"
#include "pump/transport/tls_dialer.h"

namespace pump {
namespace protocol {
    namespace http {

        client::client(service_ptr sv)
          : sv_(sv), 
            dial_timeout_(0), 
            tls_handshake_timeout_(0),
            wait_for_response_(false) {
        }

        client::~client() {
        }

        response_sptr client::request(request_sptr &req) {
            std::unique_lock<std::mutex> lock(resp_mx_);

            c_uri_ptr uri = req->get_uri();
            std::string req_host = uri->get_host();
            if (last_req_host_ != req_host) {
                __destroy_connection();
            }

            if (!conn_ || !conn_->is_valid()) {
                bool https = uri->get_type() == URI_HTTPS;
                auto peer_address = host_to_address(https, req_host);
                if (!__create_connection(https, peer_address)) {
                    return response_sptr();
                }
                last_req_host_ = uri->get_host();
            }

            if (!conn_->send(req.get()) || !conn_->read_next_pocket()) {
                return response_sptr();
            }

            wait_for_response_ = true;

            response_sptr resp;
            std::chrono::seconds timeout = std::chrono::seconds(5);
            if (resp_cond_.wait_for(lock, timeout) != std::cv_status::timeout) {
                resp = std::move(resp_);
            }

            wait_for_response_ = false;

            return resp;
        }

        bool client::__create_connection(bool https, const transport::address &peer_address) {
            transport::base_transport_sptr transp;
            transport::address bind_address("0.0.0.0", 0);
            if (https) {
                auto dialer = transport::tls_sync_dialer::create();
                transp = dialer->dial(sv_,
                                      bind_address,
                                      peer_address,
                                      dial_timeout_,
                                      tls_handshake_timeout_);
            } else {
                auto dialer = transport::tcp_sync_dialer::create();
                transp = dialer->dial(sv_, bind_address, peer_address, dial_timeout_);
            }

            if (!transp) {
                return false;
            }

            conn_.reset(new connection(false, transp));

            http_callbacks cbs;
            client_wptr cli = shared_from_this();
            cbs.error_cb = pump_bind(&client::on_error, cli, conn_.get(), _1);
            cbs.pocket_cb = pump_bind(&client::on_response, cli, conn_.get(), _1);

            return conn_->start(sv_, cbs);
        }

        void client::__destroy_connection() {
            if (conn_) {
                conn_->stop();
                conn_.reset();
            }
        }

        void client::__notify_response(connection_ptr conn, response_sptr &&resp) {
            std::unique_lock<std::mutex> lock(resp_mx_);
            if (wait_for_response_ && conn == conn_.get()) {
                resp_ = resp;
                resp_cond_.notify_one();
            }
        }

        void client::on_response(client_wptr wptr, connection_ptr conn, pocket_sptr &&pk) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->__notify_response(conn, std::static_pointer_cast<response>(pk));
            }
        }

        void client::on_error(client_wptr wptr, connection_ptr conn, const std::string &msg) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->__notify_response(conn, response_sptr());
            }
        }
    }  // namespace http
}  // namespace protocol
}  // namespace pump
