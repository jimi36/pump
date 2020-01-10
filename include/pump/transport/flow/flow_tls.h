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

#ifndef pump_transport_flow_tls_h
#define pump_transport_flow_tls_h

#include "pump/transport/flow/flow.h"

namespace pump {
	namespace transport {
		namespace flow {

			struct tls_session;
			DEFINE_ALL_POINTER_TYPE(tls_session);

			class ssl_net_layer;

			class flow_tls: public flow_base
			{
			public:
				friend class ssl_net_layer;

			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_tls();

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_tls();

				/*********************************************************************************
				 * Init flow
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 init(poll::channel_sptr &ch, int32 fd, void_ptr tls_cert, bool is_client);

				/*********************************************************************************
				 * Rebind channel
				 ********************************************************************************/
				void rebind_channel(poll::channel_sptr &ch);

				/*********************************************************************************
				 * Handshake
				 * Return results: 
				 *     FLOW_ERR_NO    => handshake success, no mean finished completely
				 *     FLOW_ERR_ABORT => handshake error
				 ********************************************************************************/
				int32 handshake();

				/*********************************************************************************
				 * Want to recv
				 * If using iocp this post a iocp task for connecting, else do nothing.
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 want_to_recv();

				/*********************************************************************************
				 * Recv from net
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_AGAIN => no more data on net
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 recv_from_net(net::iocp_task_ptr itask);

				/*********************************************************************************
				 * Read from ssl
				 ********************************************************************************/
				c_block_ptr read_from_ssl(int32_ptr size);

				/*********************************************************************************
				 * Write to ssl
				 * If happened error return -1, Otherwise return size of buffer wrote.
				 ********************************************************************************/
				int32 write_to_ssl(buffer_ptr wb);

				/*********************************************************************************
				 * Want to send
				 * If using iocp this post an iocp task for sending, else this try sending data.
				 * Return results: 
				 *     FLOW_ERR_NO      => success
				 *     FLOW_ERR_NO_DATA => no data to send
				 *     FLOW_ERR_ABORT   => error
				 ********************************************************************************/
				int32 want_to_send();

				/*********************************************************************************
				 * Send to net
				 * Return results:
				 *     FLOW_ERR_NO      => send completely
				 *     FLOW_ERR_AGAIN   => try to send again
				 *     FLOW_ERR_NO_DATA => no data to send
				 *     FLOW_ERR_ABORT   => error
				 ********************************************************************************/
				int32 send_to_net(net::iocp_task_ptr itask);

				/*********************************************************************************
				 * Check there are data to send or not
				 ********************************************************************************/
				bool has_data_to_send() 
				{ 
					return net_send_buffer_.data_size() > 0 || !ssl_send_cache_.empty();
				}

				/*********************************************************************************
				 * Check handshaked status
				 ********************************************************************************/
				bool is_handshaked() const { return is_handshaked_; }

			private:
				/*********************************************************************************
				 * Read from net recv cache
				 ********************************************************************************/
				uint32 __read_from_net_recv_cache(block_ptr b, uint32 maxlen);

				/*********************************************************************************
				 * write to net send cache
				 ********************************************************************************/
				void __write_to_net_send_cache(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Get ssl session
				 ********************************************************************************/
				tls_session_ptr __get_tls_cert() { return session_; }

			private:
				bool is_handshaked_;

				// GunTLS session 
				tls_session_ptr session_;

				// Recv iocp task
				net::iocp_task_ptr recv_task_;
				// Net recv cache
				std::string net_recv_cache_;
				// Net recv buffer
				std::string net_recv_buffer_;
				// TLS read buffer
				std::string ssl_read_buffer_;

				// Recv iocp task
				net::iocp_task_ptr send_task_;
				// Net send buffer
				buffer net_send_buffer_;
				// TLS send cache
				std::string ssl_send_cache_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_tls);

		}
	}
}

#endif