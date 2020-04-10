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

#include "pump/transport/tls_handshaker.h"

namespace pump {
	namespace transport {

		const int32 TLS_HANDSHAKE_DONE  = 0;
		const int32 TLS_HANDSHAKE_DOING = 1;
		const int32 TLS_HANDSHAKE_ERROR = 2;

		tls_handshaker::tls_handshaker() :
			transport_base(TLS_HANDSHAKER, nullptr, -1)
		{
		}

		bool tls_handshaker::init(
			int32 fd,
			bool is_client,
			void_ptr tls_cert,
			const address &local_address,
			const address &remote_address
		) {
			if (!__open_flow(fd, tls_cert, is_client))
				return false;

			local_address_  = local_address;
			remote_address_ = remote_address;

			return true;
		}

		bool tls_handshaker::start(
			service_ptr sv, 
			int64 timeout, 
			tls_handshaked_notifier_sptr &notifier
		) {
			if (!flow_)
				return false;

			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(notifier, __set_notifier(notifier));

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__start_tracker())
				return false;

			if (!__start_timer(timeout))
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		bool tls_handshaker::start(
			service_ptr sv,
			poll::channel_tracker_sptr &tracker,
			int64 timeout,
			tls_handshaked_notifier_sptr &notifier
		) {
			if (!flow_)
				return false;

			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(notifier, __set_notifier(notifier));

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__restart_tracker(tracker))
				return false;

			if (!__start_timer(timeout))
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void tls_handshaker::stop()
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING))
			{
				__stop_timer();
				__close_flow();
				__stop_tracker();
				return;
			}

			if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING) ||
				__set_status(TRANSPORT_TIMEOUT_DOING, TRANSPORT_STOPPING))
				return;
		}

		void tls_handshaker::on_read_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false, 
				return);

			if (flow->read_from_net(itask) == FLOW_ERR_ABORT)
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}

			flow->end_read_task();

			PUMP_LOCK_SPOINTER_EXPR(tracker, tracker_, false,
				return);
			
			switch (__process_handshake(flow, tracker))
			{
			case TLS_HANDSHAKE_DONE:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISH))
				{
					__stop_timer();
					__stop_tracker();
				}
				break;
			case TLS_HANDSHAKE_DOING:
				__awake_tracker(tracker);
				break;
			default:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				break;
			}
		}

		void tls_handshaker::on_send_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return);

			PUMP_LOCK_SPOINTER_EXPR(tracker, tracker_, false,
				return);

			switch (flow->send_to_net(itask))
			{
			case FLOW_ERR_ABORT:
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}
			case FLOW_ERR_AGAIN:
				__awake_tracker(tracker);
				return;
			case FLOW_ERR_NO_DATA:
			case FLOW_ERR_NO:
				break;
			}
			
			switch (__process_handshake(flow, tracker))
			{
			case TLS_HANDSHAKE_DONE:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISH))
				{
					__stop_timer();
					__stop_tracker();
				}
				break;
			case TLS_HANDSHAKE_DOING:
				__awake_tracker(tracker);
				break;
			default:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				break;
			}
		}

		void tls_handshaker::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				if (__is_status(TRANSPORT_FINISH))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<tls_handshaked_notifier>(), true,
						notifier->on_handshaked_callback(this, true));
				}
				else if (__is_status(TRANSPORT_ERROR))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<tls_handshaked_notifier>(), true,
						notifier->on_handshaked_callback(this, false));
				}
				else if (__set_status(TRANSPORT_TIMEOUT_DOING, TRANSPORT_TIMEOUT_DONE))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<tls_handshaked_notifier>(), true,
						notifier->on_handshaked_timeout_callback(this));
				}
				else if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<tls_handshaked_notifier>(), true,
						notifier->on_handshaked_callback(this, false));
				}
				else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<tls_handshaked_notifier>(), true,
						notifier->on_stopped_handshaking_callback(this));
				}
			}
		}

		void tls_handshaker::on_timer_timeout(void_ptr arg)
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUT_DOING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		bool tls_handshaker::__open_flow(int32 fd, void_ptr tls_cert, bool is_client)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tls());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, fd, tls_cert, is_client) != FLOW_ERR_NO)
				return false;

			// Set channel FD
			poll::channel::__set_fd(fd);

			return true;
		}

		int32 tls_handshaker::__process_handshake(
			flow::flow_tls_ptr flow, 
			poll::channel_tracker_ptr tracker
		) {
			if (flow->handshake() != FLOW_ERR_NO)
				return TLS_HANDSHAKE_ERROR;

			if (flow->has_data_to_send())
			{
				switch (flow->want_to_send())
				{
				case FLOW_ERR_ABORT:
					return TLS_HANDSHAKE_ERROR;
				case FLOW_ERR_NO:
					tracker->set_event(TRACK_WRITE);
					return TLS_HANDSHAKE_DOING;
				case FLOW_ERR_NO_DATA:
					PUMP_ASSERT(false);
				default:
					PUMP_ASSERT(false);
				}
			}

			if (!flow->is_handshaked())
			{
				if (flow->beg_read_task() != FLOW_ERR_NO)
					return TLS_HANDSHAKE_ERROR;

				tracker->set_event(TRACK_READ);

				return TLS_HANDSHAKE_DOING;
			}

			return TLS_HANDSHAKE_DONE;
		}

		bool tls_handshaker::__start_timer(int64 timeout)
		{
			if (timeout <= 0)
				return true;

			PUMP_ASSERT(!timer_);
			time::timeout_notifier_sptr notifier = shared_from_this();
			timer_.reset(new time::timer(nullptr, notifier, timeout));

			return get_service()->start_timer(timer_);
		}

		void tls_handshaker::__stop_timer()
		{
			if (timer_)
				timer_->stop();
		}

		bool tls_handshaker::__start_tracker()
		{
			PUMP_ASSERT(!tracker_);
			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_NONE, TRACK_MODE_ONCE));
			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			if (__process_handshake(flow_.get(), tracker_.get()) == TLS_HANDSHAKE_ERROR)
				return false;

			return true;
		}

		bool tls_handshaker::__restart_tracker(poll::channel_tracker_sptr &tracker)
		{
			PUMP_ASSERT(tracker->get_mode() == TRACK_MODE_ONCE);
			PUMP_ASSERT_EXPR(tracker, tracker_ = tracker);

			poll::channel_sptr ch = shared_from_this();
			tracker_->set_channel(ch);
			
			if (!get_service()->awake_channel_tracker(tracker_.get()))
				PUMP_ASSERT(false);

			tracker_cnt_.fetch_add(1);

			if (__process_handshake(flow_.get(), tracker_.get()) == TLS_HANDSHAKE_ERROR)
				return false;

			return true;
		}

		void tls_handshaker::__stop_tracker()
		{
			if (!tracker_)
				return;

			if (!get_service()->remove_channel_tracker(tracker_))
				PUMP_ASSERT(false);

			tracker_.reset();
		}

		void tls_handshaker::__awake_tracker(poll::channel_tracker_ptr tracker)
		{
			if (!get_service()->awake_channel_tracker(tracker))
				PUMP_ASSERT(false);
		}

	}
}