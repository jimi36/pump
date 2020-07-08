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

#ifndef pump_protocol_websocket_server_h
#define pump_protocol_websocket_server_h

#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tls_acceptor.h"
#include "pump/protocol/websocket/connection.h"

namespace pump {
	namespace protocol {
		namespace websocket {

			class server;
			DEFINE_ALL_POINTER_TYPE(server);

			class LIB_PUMP ws_router
			{
			public:
				typedef pump_function<void(connection_sptr&)> route_callback;

			public:
				/*********************************************************************************
				 * Append router
				 ********************************************************************************/
				PUMP_INLINE void append(
					const std::string &path,
					const route_callback &r
				) {
					routers_[path] = r;
				}

				/*********************************************************************************
				 * Route
				 * If no found router with the path return false.
				 ********************************************************************************/
				PUMP_INLINE bool route(const std::string &path, connection_sptr &conn)
				{
					auto it = routers_.find(path);
					if (it != routers_.end())
					{
						it->second(conn);
						return true;
					}
					return false;
				}

				/*********************************************************************************
				 * Check route has or not
				 ********************************************************************************/
				PUMP_INLINE bool has_route(const std::string &path) const
				{
					return routers_.find(path) != routers_.end();
				}

			private:
				std::map<std::string, route_callback> routers_;
			};

			class LIB_PUMP server :
				public std::enable_shared_from_this<server>
			{
			public:
				typedef pump_function<service_ptr()> select_service_callback;

				struct ws_upgarde_config
				{
					std::string host;
					std::string origin;
					std::string protoc;
				};

			public:
				/*********************************************************************************
				 * Create instance
				 ********************************************************************************/
				PUMP_INLINE static server_sptr create_instance()
				{
					return server_sptr(new server);
				}

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~server() = default;

				/*********************************************************************************
				 * Append route
				 ********************************************************************************/
				PUMP_INLINE void append_route(
					const std::string &path,
					const ws_router::route_callback &rcb
				) {
					router_.append(path, rcb);
				}

				/*********************************************************************************
				 * Start
				 ********************************************************************************/
				bool start(
					service_ptr sv,
					const transport::address &listen_address,
					const std::map<std::string, std::string> &local_headers
				);

				/*********************************************************************************
				 * Start
				 ********************************************************************************/
				bool start(
					service_ptr sv,
					const std::string &crtfile,
					const std::string &keyfile,
					const transport::address &listen_address,
					const std::map<std::string, std::string> &local_headers
				);

				/*********************************************************************************
				 * Stop
				 ********************************************************************************/
				void stop();

				/*********************************************************************************
				 * Set select service callabck
				 ********************************************************************************/
				PUMP_INLINE void set_select_service_callabck(
					const select_service_callback &cb
				) {
					select_service_cb_ = cb;
				}

			protected:
				/*********************************************************************************
				 * Acceptor accepted callback
				 ********************************************************************************/
				static void on_accepted(server_wptr wptr, transport::base_transport_sptr transp);

				/*********************************************************************************
				 * Acceptor stopped callback
				 ********************************************************************************/
				static void on_stopped(server_wptr wptr);

				/*********************************************************************************
				 * Upgrade request callback
				 ********************************************************************************/
				static void on_upgrade_request(
					server_wptr wptr,
					http::connection_wptr wptr_http_conn,
					http::pocket_sptr &pk
				);

				/*********************************************************************************
				 * Upgrade error callback
				 ********************************************************************************/
				static void on_upgrade_error(
					server_wptr wptr,
					http::connection_wptr wconn,
					const std::string& msg
				);

			private:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				server() noexcept;

				/*********************************************************************************
				 * Handle http upgrade request
				 ********************************************************************************/
				bool __handle_upgrade_request(http::connection_ptr conn, http::c_request_ptr req);

				/*********************************************************************************
				 * Stop all upgrading connections
				 ********************************************************************************/
				void __stop_all_upgrading_conns();

				/*********************************************************************************
				 * Get local header
				 ********************************************************************************/
				const std::string& __get_local_header(
					const std::string &name
				) const;

			private:
				// Service 
				service_ptr sv_;
				// Acceptor 
				transport::base_acceptor_sptr acceptor_;

				// Select service callback
				select_service_callback select_service_cb_;

				// Upgrading http connections
				std::mutex http_conn_mx_;
				std::map<void_ptr, http::connection_sptr> http_conns_;

				// Websocket upgrade request headers filter
				std::map<std::string, std::string> local_headers_;

				// Websocket router
				ws_router router_;
			};

		}
	}
}

#endif
