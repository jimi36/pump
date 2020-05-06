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
			PUMP_CONST address &local_address,
			PUMP_CONST address &remote_address,
			int64 connect_timeout
		) PUMP_NOEXCEPT : 
			base_dialer(TCP_DIALER, local_address, remote_address, connect_timeout)
		{
		}

		bool tcp_dialer::start(service_ptr sv, PUMP_CONST dialer_callbacks &cbs)
		{
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.dialed_cb && cbs.stopped_cb && cbs.timeout_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__open_flow())
				return false;

			if (!__start_tracker((poll::channel_sptr)shared_from_this()))
				return false;

			if (flow_->want_to_connect(remote_address_) != FLOW_ERR_NO)
				return false;

			if (!__start_connect_timer(function::bind(&tcp_dialer::on_timeout, shared_from_this())))
				return false;

			PUMP_DEBUG_CHECK(__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED));

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
				__stop_tracker();
				__stop_connect_timer();
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
			auto flow = flow_.get();

			address local_address, remote_address;
			bool success = (flow->connect(itask, &local_address, &remote_address) == 0);

			int32 next_status = success ? TRANSPORT_FINISH : TRANSPORT_ERROR;
			if (!__set_status(TRANSPORT_STARTED, next_status))
				return;

			__close_flow();
			__stop_tracker();
			__stop_connect_timer();

			tcp_transport_sptr conn;
			if (success)
			{
				conn = tcp_transport::create_instance();
				PUMP_DEBUG_CHECK(conn->init(flow->unbind_fd(), local_address, remote_address));
			}

			cbs_.dialed_cb(conn, success);
		}

		void tcp_dialer::on_timeout(tcp_dialer_wptr wptr)
		{
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			if (dialer->__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUT_DOING))
			{
				dialer->__close_flow();
				dialer->__stop_tracker();
			}
		}

		bool tcp_dialer::__open_flow()
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tcp_dialer());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, local_address_) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			return true;
		}

		base_transport_sptr tcp_sync_dialer::dial(
			service_ptr sv,
			PUMP_CONST address &local_address,
			PUMP_CONST address &remote_address,
			int64 connect_timeout
		) {
			base_transport_sptr transp;

			if (dialer_)
				return transp;

			dialer_callbacks cbs;
			cbs.dialed_cb = function::bind(&tcp_sync_dialer::on_dialed_callback, 
				shared_from_this(), _1, _2);
			cbs.timeout_cb = function::bind(&tcp_sync_dialer::on_timeout_callback,
				shared_from_this());
			cbs.stopped_cb = function::bind(&tcp_sync_dialer::on_stopped_callback);

			dialer_ = tcp_dialer::create_instance(local_address, remote_address, connect_timeout);
			if (!dialer_->start(sv, cbs))
			{
				dialer_.reset();
				return transp;
			}

			auto future = dial_promise_.get_future();
			transp = future.get();

			return transp;
		}

		void tcp_sync_dialer::on_dialed_callback(
			tcp_sync_dialer_wptr wptr,
			base_transport_sptr transp,
			bool succ
		) {
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			dialer->dial_promise_.set_value(transp);
		}

		void tcp_sync_dialer::on_timeout_callback(tcp_sync_dialer_wptr wptr) 
		{
			PUMP_LOCK_WPOINTER(dialer, wptr);
			if (dialer == nullptr)
				return;

			dialer->dial_promise_.set_value(base_transport_sptr());
		}

		void tcp_sync_dialer::on_stopped_callback()
		{
			PUMP_ASSERT(false);
		}

	}
}
