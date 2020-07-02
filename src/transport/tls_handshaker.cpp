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

		PUMP_CONST int32 TLS_HANDSHAKE_DONE  = 0;
		PUMP_CONST int32 TLS_HANDSHAKE_DOING = 1;
		PUMP_CONST int32 TLS_HANDSHAKE_ERROR = 2;

		tls_handshaker::tls_handshaker() PUMP_NOEXCEPT : 
			base_channel(TYPE_TLS_HANDSHAKER, nullptr, -1)
		{
		}

		void tls_handshaker::init(
			int32 fd,
			bool is_client,
			void_ptr xcred,
			PUMP_CONST address &local_address,
			PUMP_CONST address &remote_address
		) {
			local_address_ = local_address;
			remote_address_ = remote_address;

			PUMP_ASSERT(__open_flow(fd, xcred, is_client));
		}

		bool tls_handshaker::start(
			service_ptr sv, 
			int64 timeout, 
			PUMP_CONST tls_handshaker_callbacks &cbs
		) {
			if (!__set_status(STATUS_NONE, STATUS_STARTING))
				return false;

			PUMP_ASSERT(flow_);
			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.handshaked_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(STATUS_STARTING, STATUS_ERROR);
			});

			if (!__start_tracker())
				return false;

			if (!__start_timer(timeout))
				return false;

			defer.clear();

			PUMP_DEBUG_CHECK(
				__set_status(STATUS_STARTING, STATUS_STARTED)
			);

			return true;
		}

		bool tls_handshaker::start(
			service_ptr sv,
			poll::channel_tracker_sptr &tracker,
			int64 timeout,
			PUMP_CONST tls_handshaker_callbacks &cbs
		) {
			if (!__set_status(STATUS_NONE, STATUS_STARTING))
				return false;

			PUMP_ASSERT(flow_);
			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.handshaked_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(STATUS_STARTING, STATUS_ERROR);
			});

			if (!__restart_tracker(tracker))
				return false;

			if (!__start_timer(timeout))
				return false;

			defer.clear();

			PUMP_DEBUG_CHECK(
				__set_status(STATUS_STARTING, STATUS_STARTED)
			);

			return true;
		}

		void tls_handshaker::stop()
		{
			if (__set_status(STATUS_STARTED, STATUS_STOPPING))
			{
				__stop_timer();
				__close_flow();
				__stop_tracker();
				return;
			}

			if (__set_status(STATUS_DISCONNECTING, STATUS_STOPPING) ||
				__set_status(STATUS_TIMEOUTING, STATUS_STOPPING))
				return;
		}

		void tls_handshaker::on_read_event(net::iocp_task_ptr itask)
		{
			auto flow = flow_.get();
			if (flow->read_from_net(itask) == FLOW_ERR_ABORT)
			{
				if (__set_status(STATUS_STARTED, STATUS_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}

			PUMP_LOCK_SPOINTER(tracker, tracker_);
			if (tracker == nullptr)
				return;

			auto ret = __process_handshake(flow, tracker);
			if (ret == TLS_HANDSHAKE_DONE)
			{
				if (__set_status(STATUS_STARTED, STATUS_FINISHED))
				{
					__stop_timer();
					__stop_tracker();
				}
			}
			else if (ret == TLS_HANDSHAKE_DOING)
			{
				__awake_tracker(tracker);
			}
			else
			{
				if (__set_status(STATUS_STARTED, STATUS_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
			}
		}

		void tls_handshaker::on_send_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER(tracker, tracker_);
			if (tracker == nullptr)
				return;
			
			auto flow = flow_.get();
			auto ret = flow->send_to_net(itask);
			if (ret == FLOW_ERR_ABORT)
			{
				if (__set_status(STATUS_STARTED, STATUS_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}
			else if (ret == FLOW_ERR_AGAIN)
			{
				__awake_tracker(tracker);
				return;
			}
			
			ret = __process_handshake(flow, tracker);
			if (ret == TLS_HANDSHAKE_DONE)
			{
				if (__set_status(STATUS_STARTED, STATUS_FINISHED))
				{
					__stop_timer();
					__stop_tracker();
				}
			}
			else if (ret == TLS_HANDSHAKE_DOING)
			{
				__awake_tracker(tracker);
			}
			else
			{
				if (__set_status(STATUS_STARTED, STATUS_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
			}
		}

		void tls_handshaker::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
			{
				if (tracker_cnt_.fetch_sub(1) - 1 == 0)
				{
					if (__is_status(STATUS_FINISHED))
						cbs_.handshaked_cb(this, true);
					else if (__is_status(STATUS_ERROR))
						cbs_.handshaked_cb(this, false);
					else if (__set_status(STATUS_TIMEOUTING, STATUS_TIMEOUTED))
						cbs_.handshaked_cb(this, false);
					else if (__set_status(STATUS_DISCONNECTING, STATUS_DISCONNECTED))
						cbs_.handshaked_cb(this, false);
					else if (__set_status(STATUS_STOPPING, STATUS_STOPPED))
						cbs_.stopped_cb(this);
				}
			}
		}

		void tls_handshaker::on_timeout(tls_handshaker_wptr wptr)
		{
			PUMP_LOCK_WPOINTER(handshaker, wptr);
			if (handshaker == nullptr)
				return;

			if (handshaker->__set_status(STATUS_STARTED, STATUS_TIMEOUTING))
			{
				handshaker->__close_flow();
				handshaker->__stop_tracker();
			}
		}

		bool tls_handshaker::__open_flow(int32 fd, void_ptr xcred, bool is_client)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tls());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, fd, xcred, is_client) != FLOW_ERR_NO)
				return false;

			// Set channel fd
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
				tracker->set_event(TRACK_WRITE);
				if (flow->want_to_send() == FLOW_ERR_NO)
					return TLS_HANDSHAKE_DOING;
				return TLS_HANDSHAKE_ERROR;
			}

			if (!flow->is_handshaked())
			{
				tracker->set_event(TRACK_READ);
				if (flow->want_to_read() == FLOW_ERR_NO)
					return TLS_HANDSHAKE_DOING;
				return TLS_HANDSHAKE_ERROR;
			}

			return TLS_HANDSHAKE_DONE;
		}

		bool tls_handshaker::__start_timer(int64 timeout)
		{
			if (timeout <= 0)
				return true;

			PUMP_ASSERT(!timer_);
			time::timer_callback cb = function::bind(&tls_handshaker::on_timeout, shared_from_this());
			timer_ = time::timer::create_instance(timeout, cb);

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

			if (__process_handshake(flow_.get(), tracker_.get()) == TLS_HANDSHAKE_ERROR)
				return false;

			if (!get_service()->add_channel_tracker(tracker_, true))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		bool tls_handshaker::__restart_tracker(poll::channel_tracker_sptr &tracker)
		{
			PUMP_ASSERT_EXPR(tracker, tracker_ = tracker);
			PUMP_ASSERT(tracker->get_mode() == TRACK_MODE_ONCE);
			if (__process_handshake(flow_.get(), tracker_.get()) == TLS_HANDSHAKE_ERROR)
				return false;

			poll::channel_sptr ch = shared_from_this();
			tracker_->set_channel(ch);

			PUMP_DEBUG_CHECK(get_service()->awake_channel_tracker(tracker_.get()));

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tls_handshaker::__stop_tracker()
		{
			if (tracker_)
			{
				auto tracker = std::move(tracker_);
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker));
			}
		}

		void tls_handshaker::__awake_tracker(poll::channel_tracker_ptr tracker)
		{
			PUMP_DEBUG_CHECK(get_service()->awake_channel_tracker(tracker));
		}

	}
}
