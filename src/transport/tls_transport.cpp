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
			base_transport(TLS_TRANSPORT, nullptr, -1),
			sendlist_(1024),
			sendlist_size_(0),
			cur_send_buffer_(nullptr)
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

		bool tls_transport::start(service_ptr sv, const transport_callbacks &cbs)
		{
			if (!flow_)
				return false;

			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.read_cb && cbs.disconnected_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_read_tracker();
				__stop_send_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__start_all_trackers((poll::channel_sptr)shared_from_this()))
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

					if (sendlist_size_.load() == 0)
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

		bool tls_transport::send(c_block_ptr b, uint32 size)
		{
			PUMP_ASSERT(b);

			if (!__is_status(TRANSPORT_STARTED))
				return false;

			auto buffer = new flow::buffer;
			if (!buffer->append(b, size))
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
				while (true)
				{
					int32 size = 0;
					c_block_ptr b = flow->read_from_ssl(&size);
					if (size <= 0)
						break;

					cbs_.read_cb(b, size);
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

		bool tls_transport::__async_send(flow::buffer_ptr b)
		{
			if (!sendlist_.enqueue(b))
				return false;

			if (sendlist_size_.fetch_add(1) != 0 || is_sending_.test_and_set())
				return true;

			if (!sendlist_.try_dequeue(cur_send_buffer_))
				PUMP_ASSERT(false);
			PUMP_ASSERT(cur_send_buffer_);

			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false,
				return false);

			if (flow->send_to_ssl(cur_send_buffer_) <= 0)
				PUMP_ASSERT(false);
			PUMP_ASSERT(cur_send_buffer_->data_size() == 0);

			if (flow->want_to_send() == FLOW_ERR_ABORT)
				return false;

			if (!__awake_tracker(s_tracker_))
				return false;

			return true;
		}

		int32 tls_transport::__send_once(flow::flow_tls_ptr flow)
		{
			if (cur_send_buffer_)
			{
				delete cur_send_buffer_;
				cur_send_buffer_ = nullptr;
				sendlist_size_.fetch_sub(1);
			}

			if (sendlist_size_.load() > 0 && sendlist_.try_dequeue(cur_send_buffer_))
			{
				if (flow->send_to_ssl(cur_send_buffer_) <= 0)
					PUMP_ASSERT(false);
				PUMP_ASSERT(cur_send_buffer_->data_size() == 0);

				int32 ret = flow->want_to_send();
				if (ret == FLOW_ERR_NO_DATA)
					ret = FLOW_ERR_NO;
				return ret;
			}

			is_sending_.clear();

			if (sendlist_size_.load() > 0 && !is_sending_.test_and_set())
			{
				if (!sendlist_.try_dequeue(cur_send_buffer_))
					PUMP_ASSERT(false);
				PUMP_ASSERT(cur_send_buffer_);

				if (flow->send_to_ssl(cur_send_buffer_) <= 0)
					PUMP_ASSERT(false);
				PUMP_ASSERT(cur_send_buffer_->data_size() == 0);

				int32 ret = flow->want_to_send();
				if (ret == FLOW_ERR_NO_DATA)
					ret = FLOW_ERR_NO;
				return ret;
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
			if (cur_send_buffer_)
				delete cur_send_buffer_;

			flow::buffer_ptr buffer;
			while (sendlist_.try_dequeue(buffer))
			{
				delete buffer;
			}
		}

	}
}