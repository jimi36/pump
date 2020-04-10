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

#include "pump/transport/tls_transport.h"

namespace pump {
	namespace transport {

		tls_transport::tls_transport() :
			transport_base(TLS_TRANSPORT, nullptr, -1),
			sendlist_(1024)
		{
			is_sending_.clear();
		}

		tls_transport::~tls_transport()
		{
			__clear_send_pockets();
		}

		bool tls_transport::init(
			flow::flow_tls_sptr &flow,
			const address &local_address,
			const address &remote_address
		) {
			PUMP_ASSERT_EXPR(flow, flow_ = flow);

			// Flow rebind channel 
			poll::channel_sptr ch = shared_from_this();
			flow_->rebind_channel(ch);

			// Set channel FD
			poll::channel::__set_fd(flow->get_fd());

			local_address_ = local_address;
			remote_address_ = remote_address;

			return true;
		}

		bool tls_transport::start(
			service_ptr sv,
			transport_io_notifier_sptr &io_notifier,
			transport_terminated_notifier_sptr &terminated_notifier
		) {
			if (!flow_)
				return false;

			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(io_notifier, __set_notifier(io_notifier));
			PUMP_ASSERT_EXPR(terminated_notifier, __set_terminated_notifier(terminated_notifier));

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_read_tracker();
				__stop_send_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			// If using iocp, the transport is ready for sending.
			if (!net::get_iocp_handler())
				is_sending_.test_and_set();

			if (!__start_all_trackers())
				return false;

			if (flow_->beg_read_task() != FLOW_ERR_NO)
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void tls_transport::stop()
		{
			while (__is_status(TRANSPORT_STARTED) || __is_status(TRANSPORT_PAUSED))
			{
				// When in started status at the moment, stopping can be done. Then tracker event callback
				// will be triggered, we can trigger stopped callabck at there.
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING) ||
					__set_status(TRANSPORT_PAUSED, TRANSPORT_STOPPING))
				{
					// At first, stopping read tracker immediately.
					__stop_read_tracker();

					if (sendlist_.size() == 0)
					{
						__stop_send_tracker();
						__close_flow();
					}

					return;
				}
			}

			// If in disconnecting status at the moment, it means transport is disconnected but hasn't
			// triggered tracker event callback yet. So we just set stopping status to transport, and 
			// when tracker event callback triggered, we will trigger stopped callabck at there.
			if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING))
				return;
		}

		void tls_transport::force_stop()
		{
			while (__is_status(TRANSPORT_STARTED) || __is_status(TRANSPORT_PAUSED))
			{
				// When in started status at the moment, stopping can be done. Then tracker event callback
				// will be triggered, we can trigger stopped callabck at there.
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING) ||
					__set_status(TRANSPORT_PAUSED, TRANSPORT_STOPPING))
				{
					__close_flow();
					__stop_read_tracker();
					__stop_send_tracker();
					return;
				}
			}

			// If in disconnecting status at the moment, it means transport is disconnected but hasn't
			// triggered tracker event callback yet. So we just set stopping status to transport, and 
			// when tracker event callback triggered, we will trigger stopped callabck at there.
			if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING))
				return;
		}

		bool tls_transport::restart()
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (__set_status(TRANSPORT_PAUSED, TRANSPORT_STARTED))
			{
				if (flow->beg_read_task() == FLOW_ERR_ABORT)
				{
					__try_doing_disconnected_process();
					return false;
				}

				return __awake_tracker(r_tracker_);
			}
				
			return false;
		}

		bool tls_transport::pause()
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (__set_status(TRANSPORT_STARTED, TRANSPORT_PAUSED))
			{
				flow->cancel_read_task();
				return __pause_tracker(r_tracker_);
			}

			return false;
		}

		bool tls_transport::send(flow::buffer_ptr b)
		{
			PUMP_ASSERT(b);

			if (!__is_status(TRANSPORT_STARTED))
				return false;

			return __async_send(b);
		}

		bool tls_transport::send(c_block_ptr b, uint32 size, bool notify)
		{
			PUMP_ASSERT(b);

			if (!__is_status(TRANSPORT_STARTED))
				return false;

			auto buffer = new flow::buffer;
			if (!buffer || !buffer->append(b, size))
			{
				delete buffer;
				return false;
			}

			return __async_send(buffer);
		}

		void tls_transport::on_read_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return);

			switch (flow->read_from_net(itask))
			{
			case FLOW_ERR_NO:
			{
				PUMP_LOCK_SPOINTER(notifier, __get_notifier<transport_io_notifier>());
				while (true)
				{
					int32 size = 0;
					c_block_ptr b = flow->read_from_ssl(&size);
					if (size <= 0)
						break;

					if (notifier)
						notifier->on_read_callback(this, b, size);
				}
				flow->end_read_task();

				break;
			}
			case FLOW_ERR_ABORT:
				__try_doing_disconnected_process();
				return;
			}

			if (__is_status(TRANSPORT_STARTED) && flow->beg_read_task() == FLOW_ERR_ABORT)
				__try_doing_disconnected_process();
		}

		void tls_transport::on_send_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return);

			switch (flow->send_to_net(itask))
			{
			case FLOW_ERR_NO_DATA:
			case FLOW_ERR_NO:
				break;
			case FLOW_ERR_AGAIN:
				__awake_tracker(s_tracker_);
				return;
			case FLOW_ERR_ABORT:
				__try_doing_disconnected_process();
				return;
			}

			switch (__send_once(flow))
			{
			case FLOW_ERR_NO:
				__awake_tracker(s_tracker_);
				return;
			case FLOW_ERR_NO_DATA:
				break;
			case FLOW_ERR_ABORT:
				__try_doing_disconnected_process();
				return;
			}
		}

		void tls_transport::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
				{
					PUMP_LOCK_WPOINTER_EXPR(notifier, terminated_notifier_, true,
						notifier->on_disconnected_callback(this));
				}
				else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
				{
					PUMP_LOCK_WPOINTER_EXPR(notifier, terminated_notifier_, true,
						notifier->on_stopped_callback(this));
				}
			}
		}

		void tls_transport::on_channel_event(uint32 ev)
		{
			if (ev == TRANSPORT_SENT_EVENT)
			{
				PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<transport_io_notifier>(), true,
					notifier->on_sent_callback(this));
			}
		}

		bool tls_transport::__start_all_trackers()
		{
			PUMP_ASSERT(!r_tracker_ && !s_tracker_);
			poll::channel_sptr ch = shared_from_this();
			r_tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			s_tracker_.reset(new poll::channel_tracker(ch, TRACK_WRITE, TRACK_MODE_ONCE));
			if (!get_service()->add_channel_tracker(s_tracker_) ||
				!get_service()->add_channel_tracker(r_tracker_))
				return false;

			tracker_cnt_.fetch_add(2);

			return true;
		}

		bool tls_transport::__awake_tracker(poll::channel_tracker_sptr tracker)
		{
			if (!tracker)
				return false;

			if (!get_service()->awake_channel_tracker(tracker.get()))
				PUMP_ASSERT(false);

			return true;
		}

		bool tls_transport::__pause_tracker(poll::channel_tracker_sptr tracker)
		{
			if (!tracker)
				return false;

			if (!get_service()->pause_channel_tracker(tracker.get()))
				PUMP_ASSERT(false);

			return true;
		}

		void tls_transport::__stop_read_tracker()
		{
			if (!r_tracker_)
				return;

			if (!get_service()->remove_channel_tracker(r_tracker_))
				PUMP_ASSERT(false);

			r_tracker_.reset();
		}

		void tls_transport::__stop_send_tracker()
		{
			if (!s_tracker_)
				return;

			if (!get_service()->remove_channel_tracker(s_tracker_))
				PUMP_ASSERT(false);

			s_tracker_.reset();
		}

		bool tls_transport::__async_send(flow::buffer_ptr b)
		{
			sendlist_.push(b);

			flow::buffer_ptr buffer = nullptr;
			sendlist_.peek(buffer);
			if (buffer != b || is_sending_.test_and_set())
				return true;

			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (__send_once(flow) == FLOW_ERR_ABORT)
				return false;

			if (!__awake_tracker(s_tracker_))
				return false;

			return true;
		}

		int32 tls_transport::__send_once(flow::flow_tls_ptr flow)
		{
			flow::buffer_ptr buffer = nullptr;
			while (true)
			{
				if (!sendlist_.peek(buffer))
					break;

				if (buffer->data_size() > 0)
				{
					if (flow->send_to_ssl(buffer) <= 0)
						PUMP_ASSERT(false);
					PUMP_ASSERT(buffer->data_size() == 0);

					int32 ret = flow->want_to_send();
					if (ret == FLOW_ERR_NO_DATA)
						ret = FLOW_ERR_NO;
					return ret;
				}

				sendlist_.pop(buffer);

				delete buffer;
			}

			is_sending_.clear();

			if (sendlist_.peek(buffer))
			{
				if (!is_sending_.test_and_set())
				{
					if (flow->send_to_ssl(buffer) <= 0)
						PUMP_ASSERT(false);
					PUMP_ASSERT(buffer->data_size() == 0);

					int32 ret = flow->want_to_send();
					if (ret == FLOW_ERR_NO_DATA)
						ret = FLOW_ERR_NO;
					return ret;
				}
				return FLOW_ERR_NO_DATA;
			}

			// If the transport is in stopping status and no data to send, the flow should be closed
			// and the send tracker should be stopped. By the way the recv tracker no need to be 
			// stopped, beacuse it is already stopped. Then the transport will be stopped,
			if (__is_status(TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_send_tracker();
			}

			return FLOW_ERR_NO_DATA;
		}

		void tls_transport::__try_doing_disconnected_process()
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING) ||
				__set_status(TRANSPORT_PAUSED, TRANSPORT_DISCONNECTING))
			{
				__close_flow();
				__stop_read_tracker();
				__stop_send_tracker();
			}
		}

		void tls_transport::__clear_send_pockets()
		{
			flow::buffer_ptr buffer = nullptr;
			while (sendlist_.pop(buffer))
			{
				delete buffer;
			}
		}

	}
}