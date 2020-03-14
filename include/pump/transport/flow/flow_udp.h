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

#ifndef pump_transport_flow_udp_h
#define pump_transport_flow_udp_h

#include "pump/transport/flow/flow.h"

namespace pump {
	namespace transport {
		namespace flow {

			class flow_udp: public flow_base
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_udp();

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_udp();

				/*********************************************************************************
				 * Init flow
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 init(poll::channel_sptr &ch, net::iocp_handler iocp, const address &bind_address);

				/*********************************************************************************
				 * Want to read
				 * If using iocp this post an iocp task for receiving, else do nothing.
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 want_to_read();

				/*********************************************************************************
				 * Read from
				 ********************************************************************************/
				c_block_ptr read_from(net::iocp_task_ptr itask, int32_ptr size, address_ptr remote_address);

				/*********************************************************************************
				 * Send to
				 ********************************************************************************/
				int32 send_to(c_block_ptr b, uint32 size, const address &remote_addr);

			private:
				// Read iocp task
				net::iocp_task_ptr read_task_;
				// Read cache
				std::string read_cache_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_udp);

		}
	}
}

#endif