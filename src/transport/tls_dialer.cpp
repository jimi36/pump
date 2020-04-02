/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable
 law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pump/transport/tls_dialer.h"
#include "pump/transport/tls_transport.h"

namespace pump {
	namespace transport {

		tls_dialer::tls_dialer() :
			transport_base(TLS_DIALER, nullptr, -1),
			tls_cert_(nullptr),
			handshake_timeout_(0)
		{
		}

		bool tls_dialer::start(
			void_ptr tls_cert,
			service_ptr sv,
			int64 connect_timeout,
			int64 handshake_timeout,
			const address &bind_address,
			const address &connect_address,
			dialed_notifier_sptr &notifier
		) {
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(tls_cert, __set_tls_cert(tls_cert));
			PUMP_ASSERT_EXPR(notifier, __set_notifier(notifier));

			__set_tls_handshake_timeout(handshake_timeout);

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

			if (!__start_timer(connect_timeout))
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void tls_dialer::stop()
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

			// If in timeout doing status or handshaking status at the moment, it means that dialer is  
			// timeout but hasn't triggered event callback yet. So we just set stopping status to 
			// dialer, and when event callback triggered, we will trigger stopped callabck at there.
			if (__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_STOPPING) ||
				__set_status(TRANSPORT_TIMEOUT_DOING, TRANSPORT_STOPPING))
				return;
		}

		void tls_dialer::on_send_event(net::iocp_task_ptr itask)
		{
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (!flow)
			{
				flow::free_task(itask);
				return;
			}

			__stop_timer();

			address local_address, remote_address;
			if (flow->connect(itask, local_address, remote_address) != 0)
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__close_flow();
					__stop_tracker();
				}
				return;
			}

			if (!__set_status(TRANSPORT_STARTED, TRANSPORT_HANDSHAKING))
				return;

			__close_flow();

			// If handshaker is started error, handshaked callback will be triggered. So we do nothing
			// at here when started error. But if dialer stopped befere here, we shuold stop handshaking.
			handshaker_.reset(new tls_handshaker);
			if (!handshaker_->init(flow->unbind_fd(), true, tls_cert_, local_address, remote_address))
				PUMP_ASSERT(false);
			poll::channel_tracker_sptr tracker(std::move(tracker_));
			tls_handshaked_notifier_sptr notifier = shared_from_this();
			if (handshaker_->start(get_service(), tracker, handshake_timeout_, notifier))
			{
				if (__is_status(TRANSPORT_STOPPING))
					handshaker_->stop();
			}
		}

		void tls_dialer::on_tracker_event(int32 ev)
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
						notifier->on_dialed_callback(get_context(), tls_transport_sptr(), false);
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

		void tls_dialer::on_timer_timeout(void_ptr arg)
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUT_DOING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		void tls_dialer::on_handshaked_callback(transport_base_ptr handshaker, bool succ)
		{
			auto notifier_locker = __get_notifier<dialed_notifier>();
			auto notifier = notifier_locker.get();

			if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
			{
				if (notifier)
					notifier->on_stopped_dialing_callback(get_context());
			}
			else if (__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_FINISH))
			{
				tls_transport_sptr transp;
				if (succ)
				{
					auto the_handshaker = (tls_handshaker_ptr)handshaker;
					auto flow = the_handshaker->unlock_flow();
					transp = tls_transport::create_instance();
					if (!transp->init(flow, the_handshaker->get_local_address(), the_handshaker->get_remote_address()))
						PUMP_ASSERT(false);
				}

				if (notifier)
					notifier->on_dialed_callback(get_context(), transp, succ);
			}

			handshaker_.reset();
		}

		void tls_dialer::on_handshaked_timeout_callback(transport_base_ptr handshaker)
		{
			auto notifier_locker = __get_notifier<dialed_notifier>();
			auto notifier = notifier_locker.get();

			if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
			{
				if (notifier)
					notifier->on_stopped_dialing_callback(get_context());
			}
			else if (__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_TIMEOUT_DONE))
			{
				if (notifier)
					notifier->on_dialed_timeout_callback(get_context());
			}

			handshaker_.reset();
		}

		void tls_dialer::on_stopped_handshaking_callback(transport_base_ptr handshaker)
		{
			if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
			{
				auto notifier_locker = __get_notifier<dialed_notifier>();
				auto notifier = notifier_locker.get();
				if (notifier)
					notifier->on_stopped_dialing_callback(get_context());
			}
		}

		bool tls_dialer::__open_flow(const address &bind_address)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tcp_dialer());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, bind_address) != FLOW_ERR_NO)
				return false;

			// Set channel FD
			poll::channel::__set_fd(flow_->get_fd());

			// Save bind address
			bind_address_ = bind_address;

			return true;
		}

		bool tls_dialer::__start_tracker()
		{
			PUMP_ASSERT(!tracker_);
			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_WRITE, TRACK_MODE_ONCE));
			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tls_dialer::__stop_tracker()
		{
			if (!tracker_)
				return;

			if (!get_service()->remove_channel_tracker(tracker_))
				PUMP_ASSERT(false);

			tracker_.reset();
		}

		bool tls_dialer::__start_timer(int64 timeout)
		{
			if (timeout <= 0)
				return true;

			PUMP_ASSERT(!timer_);
			time::timeout_notifier_sptr notifier = shared_from_this();
			timer_.reset(new time::timer(nullptr, notifier, timeout));

			return get_service()->start_timer(timer_);
		}

		void tls_dialer::__stop_timer()
		{
			if (timer_)
				timer_->stop();
		}

	}
}
