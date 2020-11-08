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

#include "pump/transport/tcp_dialer.h"
#include "pump/transport/tls_dialer.h"
#include "pump/protocol/websocket/utils.h"
#include "pump/protocol/websocket/client.h"

namespace pump {
namespace protocol {
    namespace websocket {

        client::client() noexcept : started_(false), sv_(nullptr), upgraded_(false) {
        }

        bool client::start(service_ptr sv,
                           const client_callbacks &cbs,
                           const std::string &url,
                           const std::map<std::string, std::string> &headers) {
            // Check service.
            if (!sv) {
                return false;
            }

            // Check callbacks.
            if (!cbs.started_cb ||!cbs.data_cb || !cbs.error_cb) {
                return false;
            }

            // Set and check started state.
            if (started_.exchange(true)) {
                return false;
            }

            sv_ = sv;

            cbs_ = cbs;

            if (!__start(url, headers)) {
                return false;
            }

            return true;
        }

        void client::stop() {
            // Set and check started state.
            if (!started_.exchange(false)) {
                return;
            }
            // Stop dialer.
            if (dialer_ && dialer_->is_started()) {
                dialer_->stop();
            }
            // Stop connection.
            if (conn_ && conn_->is_valid()) {
                conn_->stop();
            }
        }

        bool client::send(c_block_ptr b, uint32 size) {
            // Check started state.
            if (!started_.load()) {
                return false;
            }
            // Check connection.
            if (!conn_ || !conn_->is_valid()) {
                return false;
            }

            return conn_->send(b, size);
        }

        void client::on_dialed(client_wptr wptr,
                               transport::base_transport_sptr &transp,
                               bool succ) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                if (!succ) {
                    cli->cbs_.error_cb("client dial error");
                    return;
                }

                upgrade_callbacks ucbs;
                ucbs.pocket_cb = pump_bind(&client::on_upgrade_response, wptr, _1);
                ucbs.error_cb = pump_bind(&client::on_error, wptr, _1);
                cli->conn_.reset(new connection(cli->sv_, transp, true));
                if (cli->conn_->start_upgrade(true, ucbs)) {
                    cli->cbs_.error_cb("client transport start error");
                    return;
                }

                std::string data;
                PUMP_ASSERT(cli->upgrade_req_);
                cli->upgrade_req_->serialize(data);
                if (!cli->conn_->send_buffer(data.c_str(), (uint32)data.size())) {
                    cli->cbs_.error_cb("client connection send upgrade request error");
                }

                // Check started state
                if (!cli->started_.load()) {
                    cli->conn_->stop();
                }
            }
        }

        void client::on_dial_timeouted(client_wptr wptr) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->cbs_.error_cb("client dial timeouted");
            }
        }

        void client::on_dial_stopped(client_wptr wptr) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->cbs_.error_cb("client dial stopped");
            }
        }

        void client::on_upgrade_response(client_wptr wptr, http::pocket_sptr pk) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                auto resp = std::static_pointer_cast<http::response>(pk);
                if (!cli->__check_upgrade_response(resp)) {
                    cli->cbs_.error_cb("client connection upgrade response invalid");
                    return;
                }

                cli->cbs_.started_cb();

                connection_callbacks cbs;
                cbs.frame_cb = pump_bind(&client::on_frame, wptr, _1, _2, _3);
                cbs.error_cb = pump_bind(&client::on_error, wptr, _1);
                if (!cli->conn_->start(cbs)) {
                    cli->cbs_.error_cb("client connection start error");
                }
            }
        }

        void client::on_frame(client_wptr wptr, c_block_ptr b, uint32 size, bool end) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->cbs_.data_cb(b, size, end);
            }
        }

        void client::on_error(client_wptr wptr, const std::string &msg) {
            PUMP_LOCK_WPOINTER(cli, wptr);
            if (cli) {
                cli->conn_.reset();
                cli->cbs_.error_cb(msg);
            }
        }

        bool client::__start(const std::string &url,
                             const std::map<std::string, std::string> &headers) {
            // Create upgrade request
            upgrade_req_.reset(new http::request(url));
            upgrade_req_->set_http_version(http::VERSION_11);
            upgrade_req_->set_method(http::METHOD_GET);
            auto u = upgrade_req_->get_uri();
            auto header = upgrade_req_->get_header();
            for (auto &h : headers) {
                header->set(h.first, h.second);
            }
            if (!header->has("Host")) {
                header->set_unique("Host", u->get_host());
            }
            header->set_unique("Connection", "Upgrade");
            header->set_unique("Upgrade", "websocket");
            header->set_unique("Sec-WebSocket-Version", "13");
            header->set_unique("Sec-WebSocket-Key", compute_sec_key());

            // Init bind address
            transport::address bind_address("0.0.0.0", 0);
            // Create transport dialer
            if (u->get_type() == http::URI_WSS) {
                auto peer_address = http::host_to_address(true, u->get_host());
                dialer_ = transport::tcp_dialer::create(
                    bind_address, peer_address, 3000);
            } else if (u->get_type() == http::URI_WS) {
                auto peer_address = http::host_to_address(false, u->get_host());
                dialer_ = transport::tls_dialer::create(
                    bind_address, peer_address, 3000, 3000);
            } else {
                return false;
            }
            // Start transport dialer
            transport::dialer_callbacks cbs;
            cbs.dialed_cb = pump_bind(&client::on_dialed, shared_from_this(), _1, _2);
            cbs.timeouted_cb = pump_bind(&client::on_dial_timeouted, shared_from_this());
            cbs.stopped_cb = pump_bind(&client::on_dial_stopped, shared_from_this());
            if (!dialer_->start(sv_, cbs)) {
                return false;
            }

            return true;
        }

        bool client::__check_upgrade_response(http::response_sptr &resp) {
            if (resp->get_status_code() != 101 ||
                resp->get_http_version() != http::VERSION_11) {
                return false;
            }

            auto header = resp->get_header();

            std::string upgrade;
            if (!header->get("Upgrade", upgrade) || upgrade != "websocket") {
                return false;
            }

            std::vector<std::string> connection;
            if (!header->get("Connection", connection) ||
                std::find(connection.begin(), connection.end(), "Upgrade") ==
                    connection.end()) {
                return false;
            }

            std::string sec_accept;
            if (!header->get("Sec-WebSocket-Accept", sec_accept)) {
                return false;
            }

            return true;
        }

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump
