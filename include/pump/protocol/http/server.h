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

#ifndef pump_protocol_http_server_h
#define pump_protocol_http_server_h

#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tls_acceptor.h"
#include "pump/protocol/http/request.h"
#include "pump/protocol/http/connection.h"

namespace pump {
	namespace protocol {
		namespace http {

			class server;
			DEFINE_ALL_POINTER_TYPE(server);

			struct server_callbacks
			{
				pump_function<
					void(connection_wptr&, request_sptr&&)
				> request_cb;

				pump_function<
					void()
				> stopped_cb;
			};

			class LIB_PUMP server : 
				public std::enable_shared_from_this<server>
			{
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
				virtual ~server();

				/*********************************************************************************
				 * Start server
				 ********************************************************************************/
				bool start(
					service_ptr sv,
					const transport::address &listen_address,
					const server_callbacks &cbs
				);

				/*********************************************************************************
				 * Start server with tls
				 ********************************************************************************/
				bool start(
					service_ptr sv,
					const std::string &crtfile,
					const std::string &keyfile,
					const transport::address &listen_address,
					const server_callbacks &cbs
				);

				/*********************************************************************************
				 * Stop server
				 ********************************************************************************/
				void stop();

			protected:
				/*********************************************************************************
				 * Acceptor accepted callback
				 ********************************************************************************/
				static void on_accepted(server_wptr wptr, transport::base_transport_sptr &&transp);

				/*********************************************************************************
				 * Acceptor stopped callback
				 ********************************************************************************/
				static void on_stopped(server_wptr wptr);

			protected:
				/*********************************************************************************
				 * Http request callback
				 ********************************************************************************/
				static void on_http_request(
					server_wptr wptr,
					connection_wptr conn,
					pocket_sptr &&pk
				);

				/*********************************************************************************
				 * Http error callback
				 ********************************************************************************/
				static void on_http_error(
					server_wptr wptr,
					connection_wptr conn,
					const std::string& msg
				);

			private:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				server() noexcept;

			private:
				// Service 
				service_ptr sv_;

				// Acceptor
				transport::base_acceptor_sptr acceptor_;

				// Connections
				std::mutex conn_mx_;
				std::condition_variable conn_cond_;
				std::map<connection_ptr, connection_sptr> conns_;

				// Server callbacks
				server_callbacks cbs_;
			};

		}
	}
}

#endif