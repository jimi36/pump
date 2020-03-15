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

#include "pump/transport/tcp_dialer.h"

namespace pump {
	namespace transport {

		tcp_dialer::tcp_dialer() :
			transport_base(TCP_DIALER, nullptr, -1)
		{
		}

		bool tcp_dialer::start(
			service_ptr sv,
			int64 timeout,
			const address &bind_address,
			const address &connect_address,
			dialed_notifier_sptr &notifier
		) {
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(notifier, __set_notifier(notifier));

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__open_flow(bind_address))
				return false;

			if (!__start_tracker())
				return false;

			if (flow_->want_to_connect(connect_address) != FLOW_ERR_NO)
				return false;

			if (!__start_timer(timeout))
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void tcp_dialer::stop()
		{
			// When in started status at the moment, stopping can be done. Then tracker event callback
			// will be triggered, we can trigger stopped callabck at there.
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_timer();
				__stop_tracker();
				return;
			}
			
			// If in timeout doing status at the moment, it means that dialer is timeout but hasn't 
			// triggered tracker event callback yet. So we just set stopping status to dialer, and
			// when tracker event callback triggered, we will trigger stopped callabck at there.
			if (__set_status(TRANSPORT_TIMEOUT_DOING, TRANSPORT_STOPPING))
				return;
		}

		void tcp_dialer::on_send_event(net::iocp_task_ptr itask)
		{
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (flow == nullptr)
			{
				// If flow no existed, it means dialer has be stopped. So we free iocp task and 
				// return at here.
				flow::free_iocp_task(itask);
				return;
			}

			address local_address, remote_address;
			bool success = (flow->connect(itask, local_address, remote_address) == 0);

			int32 next_status = success ? TRANSPORT_FINISH : TRANSPORT_ERROR;
			if (!__set_status(TRANSPORT_STARTED, next_status))
				return;

			__close_flow();
			__stop_timer();
			__stop_tracker();

			if (success)
			{
				tcp_transport_sptr conn = tcp_transport::create_instance();
				if (!conn->init(flow->unbind_fd(), local_address, remote_address))
					PUMP_ASSERT(false);

				auto notifier_locker = __get_notifier<dialed_notifier>();
				auto notifier = notifier_locker.get();
				if (notifier)
					notifier->on_dialed_callback(get_context(), conn, success);
			}
		}

		void tcp_dialer::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				auto notifier_locker = __get_notifier<dialed_notifier>();
				auto notifier = notifier_locker.get();

				if (__is_status(TRANSPORT_ERROR))
				{
					if (notifier)
						notifier->on_dialed_callback(get_context(), tcp_transport_sptr(), false);
				}
				else if (__set_status(TRANSPORT_TIMEOUT_DOING, TRANSPORT_TIMEOUT_DONE))
				{
					if (notifier)
						notifier->on_dialed_timeout_callback(get_context());
				}
				else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
				{
					if (notifier)
						notifier->on_stopped_dialing_callback(get_context());
				}
			}
		}

		void tcp_dialer::on_timer_timeout(void_ptr arg)
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUT_DOING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		bool tcp_dialer::__open_flow(const address &bind_address)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tcp_dialer());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, get_service()->get_iocp_handler(), bind_address) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			// Save bind address
			bind_address_ = bind_address;

			return true;
		}

		bool tcp_dialer::__start_tracker()
		{
			PUMP_ASSERT(!tracker_);
			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_WRITE, TRACK_MODE_ONCE));
			tracker_->set_track_status(true);

			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tcp_dialer::__stop_tracker()
		{
			if (!tracker_)
				return;

			if (!get_service()->remove_channel_tracker(tracker_))
				PUMP_ASSERT(false);

			tracker_.reset();
		}

		bool tcp_dialer::__start_timer(int64 timeout)
		{
			if (timeout <= 0)
				return true;

			PUMP_ASSERT(!timer_);
			time::timeout_notifier_sptr notifier = shared_from_this();
			timer_.reset(new time::timer(nullptr, notifier, timeout));

			return get_service()->start_timer(timer_);
		}

		void tcp_dialer::__stop_timer()
		{
			if (timer_)
				timer_->stop();
		}

	}
}
