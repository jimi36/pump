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

#ifndef pump_transport_flow_h
#define pump_transport_flow_h

#include "pump/net/iocp.h"
#include "pump/net/socket.h"
#include "pump/poll/channel.h"
#include "pump/transport/address.h"
#include "pump/transport/flow/buffer.h"

namespace pump {
	namespace transport {
		namespace flow {

			#define FLOW_ERR_NO      0
			#define	FLOW_ERR_ABORT   1
			#define FLOW_ERR_BUSY    2
			#define FLOW_ERR_AGAIN   3
			#define FLOW_ERR_NO_DATA 4

			class flow_base
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				flow_base();

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~flow_base();

				/*********************************************************************************
				 * Unbind fd
				 * This will return and unbind the fd from the flow.
				 ********************************************************************************/
				int32 unbind_fd();

				/*********************************************************************************
				 * Get fd
				 ********************************************************************************/
				int32 get_fd() const { return fd_; }

				/*********************************************************************************
				 * Check flow valid status
				 ********************************************************************************/
				bool is_valid() const { return fd_ > 0; }

			protected:
				// FD
				int32 fd_;
				// Channel
				poll::channel_wptr ch_;
				// Net extension for ICOP
				net::net_extension_ptr ext_;
			};
			DEFINE_ALL_POINTER_TYPE(flow_base);

			void free_task(net::iocp_task_ptr itask);

		}
	}
}

#endif