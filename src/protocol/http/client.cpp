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

#include "pump/transport/tcp_dialer.h"
#include "pump/transport/tls_dialer.h"
#include "pump/protocol/http/client.h"

namespace pump {
	namespace protocol {
		namespace http {

			client::client(service_ptr sv) :
				sv_(sv),
				cert_(nullptr),
				dial_timeout_(0),
				tls_handshake_timeout_(0)
			{
			}

			client::~client()
			{
			}

			response_sptr client::request(request_sptr &req)
			{
				std::unique_lock<std::mutex> lock(resp_mx_);

				if (!conn_ || !conn_->is_valid())
				{
					auto uri = req->get_uri();
					bool https = uri->get_type() == URI_HTTPS;
					auto peer_address = host_to_address(https, uri->get_host());
					if (!__create_connection(https, peer_address))
						return response_sptr();
				}
				else
				{
					conn_->get_transport()->continue_read();
				}

				if (!conn_->send(req.get()))
					return response_sptr();

				if (resp_cond_.wait_for(lock, std::chrono::seconds(5)) == std::cv_status::timeout)
					return response_sptr();

				return std::move(resp_);
			}

			bool client::__create_connection(bool https, const transport::address &peer_address)
			{
				transport::base_transport_sptr transp;

				if (https)
				{
					transport::address bind_address("0.0.0.0", 0);
					auto dialer = transport::tls_sync_dialer::create_instance();
					transp = dialer->dial(sv_, bind_address, peer_address, dial_timeout_, tls_handshake_timeout_);
				}
				else
				{
					transport::address bind_address("0.0.0.0", 0);
					auto dialer = transport::tcp_sync_dialer::create_instance();
					transp = dialer->dial(sv_, bind_address, peer_address, dial_timeout_);
				}

				if (!transp)
					return false;

				http_callbacks cbs;
				client_wptr cli = shared_from_this();
				cbs.error_cb = pump_bind(&client::on_error, cli, _1);
				cbs.pocket_cb = pump_bind(&client::on_response, cli, _1);
				conn_.reset(new connection(false, transp));
				return conn_->start(sv_, cbs);
			}

			void client::__destroy_connection()
			{
				if (conn_)
				{
					conn_->stop();
					conn_.reset();
				}
			}

			void client::__notify_response(response_sptr &resp)
			{
				std::unique_lock<std::mutex> lock(resp_mx_);
				resp_ = resp;
				resp_cond_.notify_one();
			}

			void client::on_response(client_wptr wptr, pocket_sptr &pk)
			{
				PUMP_LOCK_WPOINTER(cli, wptr);
				if (cli == nullptr)
					return;

				cli->conn_->get_transport()->pause_read();

				auto resp = std::static_pointer_cast<response>(pk);
				cli->__notify_response(resp);
			}

			void client::on_error(client_wptr wptr, const std::string& msg)
			{
				PUMP_LOCK_WPOINTER(cli, wptr);
				if (cli == nullptr)
					return;

				response_sptr resp;
				cli->__notify_response(resp);
			}
		}
	}
}
