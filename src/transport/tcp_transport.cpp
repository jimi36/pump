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

#include "pump/poll/poller.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
	namespace transport {

		tcp_transport::tcp_transport() PUMP_NOEXCEPT : 
			base_transport(TYPE_TCP_TRANSPORT, nullptr, -1),
			last_send_buffer_size_(0),
			last_send_buffer_(nullptr),
			sendlist_(1024)
		{
			next_send_chance_.clear();
		}

		tcp_transport::~tcp_transport()
		{
			__clear_sendlist();
		}

		void tcp_transport::init(
			int32 fd, 
			PUMP_CONST address &local_address, 
			PUMP_CONST address &remote_address
		) {
			PUMP_ASSERT(__open_flow(fd));

			local_address_  = local_address;
			remote_address_ = remote_address;
		}

		transport_error tcp_transport::start(
			service_ptr sv, 
			int32 max_pending_send_size,
			PUMP_CONST transport_callbacks &cbs
		) {
			if (!__set_status(STATUS_INIT, STATUS_STARTED))
				return ERROR_INVALID;

			PUMP_ASSERT(flow_);
			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.read_cb && cbs.disconnected_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_read_tracker();
				__stop_send_tracker();
				__set_status(STATUS_STARTED, STATUS_ERROR);
			});

			if (max_pending_send_size > 0)
				max_pending_send_size_ = max_pending_send_size;

			poll::channel_sptr ch = shared_from_this();
			if (!__start_all_trackers(ch, true, false))
				return ERROR_FAULT;

			if (flow_->want_to_read() == FLOW_ERR_ABORT)
				return ERROR_FAULT;

			defer.clear();
			
			return ERROR_OK;
		}

		void tcp_transport::stop()
		{
			while (__is_status(STATUS_STARTED))
			{
				// When in started status at the moment, stopping can be done, Then tracker event callback
				// will be triggered, we can trigger stopped callabck at there. 
				if (__set_status(STATUS_STARTED, STATUS_STOPPING))
				{
					// At first, stopping read tracker immediately
					__stop_read_tracker();

					if (pending_send_size_.load() == 0)
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
			if (__set_status(STATUS_DISCONNECTING, STATUS_STOPPING))
				return;
		}

		void tcp_transport::force_stop()
		{
			while (__is_status(STATUS_STARTED))
			{
				// When in started status at the moment, stopping can be done, Then tracker event callback
				// will be triggered, we can trigger stopped callabck at there.
				if (__set_status(STATUS_STARTED, STATUS_STOPPING))
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
			if (__set_status(STATUS_DISCONNECTING, STATUS_STOPPING))
				return;
		}

		transport_error tcp_transport::send(flow::buffer_ptr b)
		{
			PUMP_ASSERT(b && b->data_size() > 0);

			if (PUMP_UNLIKELY(!is_started()))
				return ERROR_INVALID;

			if (PUMP_UNLIKELY(pending_send_size_.load() >= max_pending_send_size_))
				return ERROR_AGAIN;

			__async_send(b);

			return ERROR_OK;
		}

		transport_error tcp_transport::send(c_block_ptr b, uint32 size)
		{
			PUMP_ASSERT(b && size > 0);

			if (PUMP_UNLIKELY(!is_started()))
				return ERROR_INVALID;

			if (PUMP_UNLIKELY(pending_send_size_.load() >= max_pending_send_size_))
				return ERROR_AGAIN;

			auto buffer = new flow::buffer;
			if (PUMP_UNLIKELY(buffer == nullptr || !buffer->append(b, size)))
			{
				if (buffer != nullptr)
					delete buffer;
				return ERROR_FAULT;
			}

			__async_send(buffer);
	
			return ERROR_OK;
		}

		void tcp_transport::on_read_event(net::iocp_task_ptr itask)
		{
			int32 size = 0;
			auto flow = flow_.get();
			c_block_ptr b = flow->read(itask, &size); // Read size must be equal or greater than zero.
			if (PUMP_LIKELY(size > 0))
			{
				// Read callback
				cbs_.read_cb(b, size);

				// Begin new read task
				if (__is_status(STATUS_STARTED) && flow->want_to_read() == FLOW_ERR_ABORT)
					__try_doing_disconnected_process();
			}
			else
			{
				__try_doing_disconnected_process();
			}
		}

		void tcp_transport::on_send_event(net::iocp_task_ptr itask)
		{
			auto flow = flow_.get();
			auto ret = flow->send(itask);
			if (ret == FLOW_ERR_AGAIN)
			{
				__awake_tracker(s_tracker_);
				return;
			}
			else if (ret == FLOW_ERR_ABORT)
			{
				__try_doing_disconnected_process();
				return;
			}

			// If there are more buffers to send, we should send next one immediately.
			if (pending_send_size_.fetch_sub(last_send_buffer_size_) - last_send_buffer_size_ > 0)
			{
				__send_once(flow);
				return;
			}

			// We must free next send chance because no more buffers to send.
			next_send_chance_.clear();

			// Sendlist maybe has be inserted buffers at the moment, so we need check and try to get 
			// next send chance. If success, we should send next buffer immediately.
			if (pending_send_size_.load() > 0 && !next_send_chance_.test_and_set())
			{
				__send_once(flow);
			}
			else if (__is_status(STATUS_STOPPING))
			{
				__close_flow();
				__stop_send_tracker();
			}
		}

		bool tcp_transport::__open_flow(int32 fd)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tcp());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, fd) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(fd);

			return true;
		}

		bool tcp_transport::__async_send(flow::buffer_ptr b)
		{
			// Insert buffer to sendlist.
			PUMP_DEBUG_CHECK(sendlist_.enqueue(b));

			// If there are no more buffers, we should try to get next send chance.
			if (pending_send_size_.fetch_add(b->data_size()) > 0 || next_send_chance_.test_and_set())
				return true;
			
			return __send_once(flow_.get());
		}

		bool tcp_transport::__send_once(flow::flow_tcp_ptr flow)
		{
			if (last_send_buffer_ != nullptr)
			{
				// Free last send buffer.
				delete last_send_buffer_;
				last_send_buffer_ = nullptr;

				// Reset last send buffer data size.
				last_send_buffer_size_ = 0;
			}

			// Get a buffer from sendlist to send.
			PUMP_DEBUG_CHECK(sendlist_.try_dequeue(last_send_buffer_));

			// Save last send buffer data size.
			last_send_buffer_size_ = last_send_buffer_->data_size();

			// Try to send the buffer.
			if(flow->want_to_send(last_send_buffer_) == FLOW_ERR_NO)
				return __awake_tracker(s_tracker_);
			
			// Happend error and try disconnecting.
			__try_doing_disconnected_process();

			return false;
		}

		void tcp_transport::__try_doing_disconnected_process()
		{
			if (__set_status(STATUS_STARTED, STATUS_DISCONNECTING))
			{
				__close_flow();
				__stop_read_tracker();
				__stop_send_tracker();
			}
		}

		void tcp_transport::__clear_sendlist()
		{
			if (last_send_buffer_ != nullptr)
				delete last_send_buffer_;

			flow::buffer_ptr buffer;
			while (sendlist_.try_dequeue(buffer))
			{
				delete buffer;
			}
		}

	}
}
