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

		udp_transport::udp_transport() :
			transport_base(UDP_TRANSPORT, nullptr, -1)
		{
		}

		bool udp_transport::start(
			service_ptr sv,
			const address &bind_address,
			transport_io_notifier_sptr &io_notifier,
			transport_terminated_notifier_sptr &terminated_notifier
		) {
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(io_notifier, __set_notifier(io_notifier));
			PUMP_ASSERT_EXPR(terminated_notifier, __set_terminated_notifier(terminated_notifier));

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__open_flow(bind_address))
				return false;

			if (!__start_tracker())
				return false;

			if (flow_->beg_read_task() != FLOW_ERR_NO)
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void udp_transport::stop()
		{
			while (__is_status(TRANSPORT_STARTED) || __is_status(TRANSPORT_PAUSED))
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING) ||
					__set_status(TRANSPORT_PAUSED, TRANSPORT_STOPPING))
				{
					__close_flow();
					__stop_tracker();
					return;
				}
			}
		}

		bool udp_transport::restart()
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (__set_status(TRANSPORT_PAUSED, TRANSPORT_STARTED))
			{
				int32 ret = flow->beg_read_task();
				if (ret != FLOW_ERR_NO || ret != FLOW_ERR_BUSY)
				{
					if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
					{
						__close_flow();
						__stop_tracker();
					}
					return false;
				}

				return __awake_tracker();
			}
				
			return false;
		}

		bool udp_transport::pause()
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (__set_status(TRANSPORT_STARTED, TRANSPORT_PAUSED))
			{
				flow->cancel_read_task();
				return __pause_tracker();
			}

			return false;
		}

		bool udp_transport::send(
			c_block_ptr b, 
			uint32 size, 
			const address &remote_address
		) {
			PUMP_ASSERT(b);

			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (flow->send_to(b, size, remote_address) <= 0)
				return false;

			return true;
		}

		void udp_transport::on_read_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return);

			address addr;
			int32 size = 0;
			c_block_ptr b = flow->read_from(itask, &size, &addr);
			if (size <= 0)
				return;

			auto notifier_locker = __get_notifier<transport_io_notifier>();
			auto notifier = notifier_locker.get();
			if (notifier)
				notifier->on_read_callback(this, b, size, addr);

			flow->end_read_task();

			if (__is_status(TRANSPORT_STARTED) && flow->beg_read_task() == FLOW_ERR_ABORT)
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__close_flow();
					__stop_tracker();
				}
			}
		}

		void udp_transport::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				PUMP_LOCK_WPOINTER_EXPR(notifier, terminated_notifier_, true,
					notifier->on_stopped_callback(this));
			}
		}

		bool udp_transport::__open_flow(const address &local_address)
		{
			// Setup flow.
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_udp());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, local_address) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			// Save local address
			bind_address_ = local_address;

			return true;
		}

		bool udp_transport::__start_tracker()
		{
			PUMP_ASSERT(!tracker_);
			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void udp_transport::__stop_tracker()
		{
			if (!tracker_)
				return;

			if (!get_service()->remove_channel_tracker(tracker_))
				PUMP_ASSERT(false);

			tracker_.reset();
		}

		bool udp_transport::__awake_tracker()
		{
			if (!tracker_)
				return false;

			if (!get_service()->awake_channel_tracker(tracker_.get()))
				PUMP_ASSERT(false);

			return true;
		}

		bool udp_transport::__pause_tracker()
		{
			if (!tracker_)
				return false;

			if (!get_service()->pause_channel_tracker(tracker_.get()))
				PUMP_ASSERT(false);

			return true;
		}

	}
}
