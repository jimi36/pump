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

#ifndef librabbit_transport_flow_tcp_dialer_h
#define librabbit_transport_flow_tcp_dialer_h

#include "librabbit/transport/flow/flow.h"

namespace librabbit {
	namespace transport {
		namespace flow {

			class flow_tcp_dialer: public flow_base
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_tcp_dialer();

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_tcp_dialer();

				/*********************************************************************************
				 * Init
				 ********************************************************************************/
				int32 init(poll::channel_sptr &ch, net::iocp_handler iocp, const address &bind_address);

				/*********************************************************************************
				 * Want to connect
				 * If using iocp, this will post a request for connecting to iocp. 
				 ********************************************************************************/
				int32 want_to_connect(const address &connect_address);

				/*********************************************************************************
				 * Connect
				 * Return socket error code.
				 ********************************************************************************/
				int32 connect(net::iocp_task_ptr itask, address &local_address, address &remote_address);

			private:
				bool is_ipv6_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_tcp_dialer);

		}
	}
}

#endif