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

#ifndef pump_protocol_http_client_h
#define pump_protocol_http_client_h

#include "pump/toolkit/features.h"
#include "pump/protocol/http/request.h"
#include "pump/protocol/http/connection.h"

namespace pump {
	namespace protocol {
		namespace http {

			class client;
			DEFINE_ALL_POINTER_TYPE(client);

			class LIB_PUMP client : 
				public toolkit::noncopyable,
				public std::enable_shared_from_this<client>
			{
			public:
				/*********************************************************************************
				 * Create instance
				 ********************************************************************************/
				PUMP_INLINE static client_sptr create_instance(service_ptr sv)
				{
					return client_sptr(new client(sv));
				}

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				~client();

				/*********************************************************************************
				 * Set connect timeout time
				 ********************************************************************************/
				PUMP_INLINE void set_connect_timeout(int64 timeout)
				{ dial_timeout_ = timeout > 0 ? timeout : 0; }

				/*********************************************************************************
				 * Set tls handshake timeout time
				 ********************************************************************************/
				PUMP_INLINE void set_tls_handshake_timeout(int64 timeout)
				{ tls_handshake_timeout_ = timeout > 0 ? timeout : 0; }

				/*********************************************************************************
				 * Request
				 * At first this will create http connection if there no valid http connection,
				 * then send http request to http server.
				 ********************************************************************************/
				response_sptr request(request_sptr &req);

				/*********************************************************************************
				 * Close
				 ********************************************************************************/
				PUMP_INLINE void close()
				{ __destroy_connection(); }

				/*********************************************************************************
				 * Get http connection
				 ********************************************************************************/
				PUMP_INLINE connection_sptr get_connection()
				{ return conn_; }

			private:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				client(service_ptr sv);

				/*********************************************************************************
				 * Create http connection
				 ********************************************************************************/
				bool __create_connection(bool https, const transport::address &peer_address);

				/*********************************************************************************
				 * Destroy http connection
				 ********************************************************************************/
				void __destroy_connection();

				/*********************************************************************************
				 * Destroy http connection
				 ********************************************************************************/
				void __notify_response(response_sptr &resp);

			private:
				/*********************************************************************************
				 * Handel connection response
				 ********************************************************************************/
				static void on_response(client_wptr wptr, pocket_sptr &pk);

				/*********************************************************************************
				 * Handel connection disconnected
				 ********************************************************************************/
				static void on_error(client_wptr wptr, const std::string& msg);

			private:
				// Service 
				service_ptr sv_;
				// TLS credentials
				void_ptr cert_;

				// Dial timeout ms tims
				int64 dial_timeout_;

				// TLS handshake timeout ms time
				int64 tls_handshake_timeout_;

				// Http connection
				connection_sptr conn_;

				// Response condition
				std::mutex resp_mx_;
				std::condition_variable resp_cond_;
				response_sptr resp_;
			};

		}
	}
}

#endif