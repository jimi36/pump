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

#include "pump/protocol/websocket/utils.h"
#include "pump/protocol/websocket/client.h"

namespace pump {
	namespace protocol {
		namespace websocket {

			client::client() noexcept :
				sv_(nullptr)
			{
			}

			bool client::start(
				service_ptr sv,
				const client_callbacks &cbs,
				const std::string &url,
				const std::map<std::string, std::string> &headers
			) {
				// Check started status
				if (conn_)
					return false;

				// Check service valid
				if (sv == nullptr)
					return false;

				// Check callbacks valid
				if (!cbs.data_cb || !cbs.error_cb)
					return false;

				sv_ = sv;

				cbs_ = cbs;

				auto http_cli = http::client::create_instance(sv_);
				http_cli->set_tls_handshake_timeout(3000);
				http_cli->set_connect_timeout(3000);

				auto resp = __do_upgrade_request(http_cli, url, headers);
				if (!resp)
					return false;

				if (!__check_upgrade_response(resp))
					return false;

				if (!__upgrade_http_connection(http_cli))
					return false;

				return true;
			}

			void client::stop()
			{
				if (conn_ && conn_->is_valid())
					conn_->stop();
			}

			bool client::send(c_block_ptr b, uint32 size)
			{
				if (!conn_ || !conn_->is_valid())
					return false;

				return conn_->send(b, size);
			}

			void client::on_data(client_wptr wptr, c_block_ptr b, uint32 size, bool end)
			{
				PUMP_LOCK_WPOINTER(cli, wptr);
				if (cli == nullptr)
					return;

				cli->cbs_.data_cb(b, size, end);
			}

			void client::on_error(client_wptr wptr, const std::string &msg)
			{
				PUMP_LOCK_WPOINTER(cli, wptr);
				if (cli == nullptr)
					return;

				cli->conn_.reset();

				cli->cbs_.error_cb(msg);
			}

			http::response_sptr client::__do_upgrade_request(
				http::client_sptr &http_cli,
				const std::string &url,
				const std::map<std::string, std::string> &headers
			) {
				http::request_sptr req(new http::request);
				req->set_http_version(http::VERSION_11);
				req->set_method(http::METHOD_GET);

				auto uri = req->get_uri();
				if (!uri->parse_url(url))
					return http::response_sptr();

				if (uri->get_type() == http::URI_WS)
					uri->set_type(http::URI_HTTP);
				else if (uri->get_type() == http::URI_WSS)
					uri->set_type(http::URI_HTTPS);
				else
					return http::response_sptr();

				auto header = req->get_header();
				for (auto &h : headers)
				{
					header->set(h.first, h.second);
				}
				if (!header->has("Host"))
					header->set_unique("Host", uri->get_host());
				header->set_unique("Connection", "Upgrade");
				header->set_unique("Upgrade", "websocket");
				header->set_unique("Sec-WebSocket-Version", "13");
				header->set_unique("Sec-WebSocket-Key", compute_sec_key());

				return http_cli->request(req);
			}

			bool client::__check_upgrade_response(http::response_sptr &resp)
			{
				if (resp->get_status_code() != 101 ||
					resp->get_http_version() != http::VERSION_11)
					return false;

				auto header = resp->get_header();

				std::string upgrade;
				if (!header->get("Upgrade", upgrade) || upgrade != "websocket")
					return false;

				std::vector<std::string> connection;
				if (!header->get("Connection", connection) ||
					std::find(connection.begin(), connection.end(), "Upgrade") == connection.end())
					return false;

				std::string sec_accept;
				if (!header->get("Sec-WebSocket-Accept", sec_accept))
					return false;

				return true;
			}

			bool client::__upgrade_http_connection(http::client_sptr &http_cli)
			{
				connection_callbacks cbs;
				client_wptr wptr = shared_from_this();
				cbs.error_cb = pump_bind(&client::on_error, wptr, _1);
				cbs.data_cb = pump_bind(&client::on_data, wptr, _1, _2, _3);

				connection_sptr conn(new connection(true));
				auto http_conn = http_cli->get_connection();
				if (!conn->upgrade(http_conn) || !conn->start(cbs))
					return false;

				conn_ = conn;

				return true;
			}

		}
	}
}
