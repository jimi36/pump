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

			class flow_tls : 
				public flow_base
			{
			public:
				friend class ssl_net_layer;

			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_tls() PUMP_NOEXCEPT;

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
				int32 init(poll::channel_sptr &ch, int32 fd, void_ptr cert, bool client);

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
				 * Begin read task
				 * If using IOCP this post a IOCP task for reading, else do nothing.
				 * Return results:
				 *     FLOW_ERR_BUSY  => busy for read
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 beg_read_task();

				/*********************************************************************************
				 * End read task
				 ********************************************************************************/
				void end_read_task();

				/*********************************************************************************
				 * Read from net
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_AGAIN => no more data on net
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 read_from_net(net::iocp_task_ptr itask);

				/*********************************************************************************
				 * Read from ssl
				 ********************************************************************************/
				c_block_ptr read_from_ssl(int32_ptr size);

				/*********************************************************************************
				 * Send to ssl
				 * If sent completedly return true else return false.
				 ********************************************************************************/
				bool send_to_ssl(buffer_ptr wb);

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
				PUMP_INLINE bool has_data_to_send() PUMP_CONST
				{ return net_send_buffer_.data_size() > 0; }

				/*********************************************************************************
				 * Check handshaked status
				 ********************************************************************************/
				PUMP_INLINE bool is_handshaked() PUMP_CONST
				{ return is_handshaked_; }

			private:
				/*********************************************************************************
				 * Read from net read cache
				 ********************************************************************************/
				uint32 __read_from_net_read_cache(block_ptr b, int32 maxlen);

				/*********************************************************************************
				 * Send to net send cache
				 ********************************************************************************/
				PUMP_INLINE void __send_to_net_send_cache(c_block_ptr tls_buffer, int32 size)
				{ net_send_buffer_.append(tls_buffer, size); }

				/*********************************************************************************
				 * Get ssl session
				 ********************************************************************************/
				PUMP_INLINE tls_session_ptr __get_tls_session() 
				{ return session_; }

			private:
				// Handshaked status
				bool is_handshaked_;

				// GNUTLS session 
				tls_session_ptr session_;

				// IOCP read task
				std::atomic_flag read_flag_;
				net::iocp_task_ptr read_task_;

				// Net read cache
				int32 net_read_data_pos_;
				int32 net_read_data_size_;
				int32 net_read_cache_raw_size_;
				block_ptr net_read_cache_raw_;
				std::string net_read_cache_;

				// TLS read cache
				int32 ssl_read_cache_raw_size_;
				block_ptr ssl_read_cache_raw_;
				std::string ssl_read_cache_;
				
				// IOCP send task
				net::iocp_task_ptr send_task_;

				// Net send buffer
				buffer net_send_buffer_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_tls);

		}
	}
}

#endif