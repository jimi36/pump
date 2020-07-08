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

#ifndef pump_transport_flow_tcp_h
#define pump_transport_flow_tcp_h

#include "pump/transport/flow/flow.h"

namespace pump {
	namespace transport {
		namespace flow {

			class flow_tcp : 
				public flow_base
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_tcp() noexcept;

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_tcp();

				/*********************************************************************************
				 * Init
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 init(poll::channel_sptr &ch, int32 fd);

				/*********************************************************************************
				 * Want to read
				 * If using IOCP this post an IOCP task for reading, else do nothing.
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 want_to_read();

				/*********************************************************************************
				 * Read
				 ********************************************************************************/
				c_block_ptr read(void_ptr iocp_task, int32_ptr size);

				/*********************************************************************************
				 * Want to send
				 * If using IOCP this post an IOCP task for sending, else this try sending data.
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 want_to_send(buffer_ptr sb);

				/*********************************************************************************
				 * Send
				 * Return results:
				 *     FLOW_ERR_NO      => send completely
				 *     FLOW_ERR_AGAIN   => try to send again
				 *     FLOW_ERR_NO_DATA => no data to send
				 *     FLOW_ERR_ABORT   => error
				 ********************************************************************************/
				int32 send(void_ptr iocp_task);

				/*********************************************************************************
				 * Check there are data to send or not
				 ********************************************************************************/
				PUMP_INLINE bool has_data_to_send() const
				{ return (send_buffer_ != nullptr && send_buffer_->data_size() > 0); }

			private:
				// IOCP read task
				void_ptr read_task_;

				// Read cache
				block read_cache_[MAX_FLOW_BUFFER_SIZE];

				// IOCP send task
				void_ptr send_task_;

				// Send buffer
				buffer_ptr send_buffer_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_tcp);

		}
	}
}

#endif