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

#ifndef pump_transport_flow_tcp_dialer_h
#define pump_transport_flow_tcp_dialer_h

#include "pump/transport/flow/flow.h"

namespace pump {
	namespace transport {
		namespace flow {

			class flow_tcp_dialer : 
				public flow_base
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_tcp_dialer() PUMP_NOEXCEPT;

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_tcp_dialer();

				/*********************************************************************************
				 * Init
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 init(poll::channel_sptr &ch, PUMP_CONST address &bind_address);

				/*********************************************************************************
				 * Want to connect
				 * If using iocp this post an iocp task for connecting.
				 * Return results:
				 *     FLOW_ERR_NO    => success
				 *     FLOW_ERR_ABORT => error
				 ********************************************************************************/
				int32 want_to_connect(PUMP_CONST address &remote_address);

				/*********************************************************************************
				 * Connect
				 * Return socket error code.
				 ********************************************************************************/
				int32 connect(
					net::iocp_task_ptr itask, 
					address_ptr local_address, 
					address_ptr remote_address
				);

			private:
				// IPV6
				bool is_ipv6_;
				// IOCP dial task
				net::iocp_task_ptr dial_task_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_tcp_dialer);

		}
	}
}

#endif