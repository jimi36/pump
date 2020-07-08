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

		tcp_dialer::tcp_dialer(
			const address &local_address,
			const address &remote_address,
			int64 connect_timeout
		) noexcept :
			base_dialer(TYPE_TCP_DIALER, local_address, remote_address, connect_timeout)
		{
		}

		transport_error tcp_dialer::start(
			service_ptr sv, 
			const dialer_callbacks &cbs
		) {
			if (!__set_status(STATUS_NONE, STATUS_STARTING))
				return ERROR_INVALID;

			PUMP_ASSERT(sv != nullptr);
			__set_service(sv);

			PUMP_DEBUG_ASSIGN(cbs.dialed_cb && cbs.stopped_cb && cbs.timeout_cb, cbs_, cbs);

			toolkit::defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(STATUS_STARTING, STATUS_ERROR);
			});

			if (!__open_flow())
				return ERROR_FAULT;

			poll::channel_sptr ch = shared_from_this();
			if (!__start_tracker(ch))
				return ERROR_FAULT;

			if (flow_->want_to_connect(remote_address_) != FLOW_ERR_NO)
				return ERROR_FAULT;

			if (!__start_connect_timer(pump_bind(&tcp_dialer::on_timeout, shared_from_this())))
				return ERROR_FAULT;

			defer.clear();

			PUMP_DEBUG_CHECK(
				__set_status(STATUS_STARTING, STATUS_STARTED)
			);

			return ERROR_OK;
		}

		void tcp_dialer::stop()
		{
			// When stopping done, tracker event will trigger stopped callback.
			if (__set_status(STATUS_STARTED, STATUS_STOPPING))
			{
				__close_flow();
				__stop_tracker();
				__stop_connect_timer();
				return;
			}
			
			// If in timeouting status at the moment, it means that dialer is timeout but hasn't 
			// triggered tracker event callback yet. So we just set it to stopping status, then
			// tracker event will trigger stopped callabck.
			if (__set_status(STATUS_TIMEOUTING, STATUS_STOPPING))
				return;
		}

		void tcp_dialer::on_send_event(void_ptr iocp_task)
		{
			auto flow = flow_.get();

			address local_address, remote_address;
			bool success = (flow->connect(iocp_task, &local_address, &remote_address) == 0);

			int32 next_status = success ? STATUS_FINISHED : STATUS_ERROR;
			if (!__set_status(STATUS_STARTED, next_status))
				return;

			__stop_tracker();
			__stop_connect_timer();

			tcp_transport_sptr conn;
			if (success)
			{
				conn = tcp_transport::create_instance();
				conn->init(flow->unbind_fd(), local_address, remote_address);
			}
			else
			{
				__close_flow();
			}

			cbs_.dialed_cb(conn, success);
		}

		void tcp_dialer::on_timeout(tcp_dialer_wptr wptr)
		{
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			if (dialer->__set_status(STATUS_STARTED, STATUS_TIMEOUTING))
			{
				dialer->__close_flow();
				dialer->__stop_tracker();
			}
		}

		bool tcp_dialer::__open_flow()
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(
				object_create<flow::flow_tcp_dialer>(), 
				object_delete<flow::flow_tcp_dialer>
			);

			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, local_address_) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			return true;
		}

		base_transport_sptr tcp_sync_dialer::dial(
			service_ptr sv,
			const address &local_address,
			const address &remote_address,
			int64 connect_timeout
		) {
			base_transport_sptr transp;

			if (dialer_)
				return base_transport_sptr();

			dialer_callbacks cbs;
			cbs.dialed_cb = pump_bind(&tcp_sync_dialer::on_dialed, shared_from_this(), _1, _2);
			cbs.timeout_cb = pump_bind(&tcp_sync_dialer::on_timeouted, shared_from_this());
			cbs.stopped_cb = pump_bind(&tcp_sync_dialer::on_stopped);

			dialer_ = tcp_dialer::create_instance(local_address, remote_address, connect_timeout);
			if (dialer_->start(sv, cbs) != ERROR_OK)
				return base_transport_sptr();

			return dial_promise_.get_future().get();
		}

		void tcp_sync_dialer::on_dialed(
			tcp_sync_dialer_wptr wptr,
			base_transport_sptr transp,
			bool succ
		) {
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			dialer->dial_promise_.set_value(transp);
		}

		void tcp_sync_dialer::on_timeouted(tcp_sync_dialer_wptr wptr) 
		{
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			dialer->dial_promise_.set_value(base_transport_sptr());
		}

		void tcp_sync_dialer::on_stopped()
		{
			PUMP_ASSERT(false);
		}

	}
}
