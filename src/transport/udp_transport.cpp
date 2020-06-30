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

#include "pump/utils/features.h"
#include "pump/transport/udp_transport.h"

namespace pump {
	namespace transport {

		udp_transport::udp_transport(PUMP_CONST address &local_address) PUMP_NOEXCEPT :
			base_transport(TYPE_UDP_TRANSPORT, nullptr, -1)
		{
			local_address_ = local_address;
		}

			transport_error udp_transport::start(
			service_ptr sv, 
			int32 max_pending_send_size,
			PUMP_CONST transport_callbacks &cbs
		) {
			if (!__set_status(STATUS_INIT, STATUS_STARTED))
				return ERROR_INVALID;

			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.read_from_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_read_tracker();
				__set_status(STATUS_STARTED, STATUS_ERROR);
			});

			if (!__open_flow())
				return ERROR_FAULT;

			if (!__start_read_tracker())
				return ERROR_FAULT;

			if (flow_->want_to_read() != FLOW_ERR_NO)
				return ERROR_FAULT;

			defer.clear();

			return ERROR_OK;
		}

		void udp_transport::stop()
		{
			while (__is_status(STATUS_STARTED))
			{
				if (__set_status(STATUS_STARTED, STATUS_STOPPING))
				{
					__close_flow();
					__stop_read_tracker();
					return;
				}
			}
		}

		transport_error udp_transport::send(
			c_block_ptr b, 
			uint32 size, 
			PUMP_CONST address &remote_address
		) {
			PUMP_ASSERT(b && size > 0);

			if (PUMP_UNLIKELY(!is_started()))
				return ERROR_INVALID;

			flow_->send(b, size, remote_address);

			return ERROR_OK;
		}

		void udp_transport::on_read_event(net::iocp_task_ptr itask)
		{
			address addr;
			int32 size = 0;
			auto flow = flow_.get();
			c_block_ptr b = flow->read_from(itask, &size, &addr);
			if (size > 0)
				cbs_.read_from_cb(b, size, addr);

			if (__is_status(STATUS_STARTED) && flow->want_to_read() == FLOW_ERR_ABORT)
			{
				if (__set_status(STATUS_STARTED, STATUS_ERROR))
				{
					__close_flow();
					__stop_read_tracker();
				}
			}
		}

		bool udp_transport::__open_flow()
		{
			// Setup flow.
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_udp());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, local_address_) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			return true;
		}

		bool udp_transport::__start_read_tracker()
		{
			PUMP_ASSERT(!r_tracker_);
			poll::channel_sptr ch = shared_from_this();
			r_tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			if (!get_service()->add_channel_tracker(r_tracker_, true))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

	}
}
