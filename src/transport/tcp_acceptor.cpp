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

#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
	namespace transport {

		tcp_acceptor::tcp_acceptor(PUMP_CONST address &listen_address) PUMP_NOEXCEPT : 
			base_acceptor(TYPE_TCP_ACCEPTOR, listen_address)
		{}

		transport_error tcp_acceptor::start(
			service_ptr sv, 
			PUMP_CONST acceptor_callbacks &cbs
		) {
			if (!__set_status(STATUS_NONE, STATUS_STARTING))
				return ERROR_INVALID;

			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.accepted_cb && cbs.stopped_cb, cbs_ = cbs);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(STATUS_STARTING, STATUS_ERROR);
			});

			if (!__open_flow())
				return ERROR_FAULT;

			poll::channel_sptr ch = shared_from_this();
			if (!__start_tracker(ch))
				return ERROR_FAULT;

			if (flow_->want_to_accept() != FLOW_ERR_NO)
				return ERROR_FAULT;

			defer.clear();

			PUMP_DEBUG_CHECK(
				__set_status(STATUS_STARTING, STATUS_STARTED)
			);

			return ERROR_OK;
		}

		void tcp_acceptor::stop()
		{
			// When stopping done, tracker event will trigger stopped callabck.
			if (__set_status(STATUS_STARTED, STATUS_STOPPING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		void tcp_acceptor::on_read_event(net::iocp_task_ptr itask)
		{
			auto flow = flow_.get();

			address local_address, remote_address;
			int32 fd = flow->accept(itask, &local_address, &remote_address);
			if (fd > 0)
			{
				auto conn = tcp_transport::create_instance();
				conn->init(fd, local_address, remote_address);

				cbs_.accepted_cb(conn);
			}

			// Acceptor maybe be stopped, so we need check it in started status.
			if (__is_status(STATUS_STARTED) && flow->want_to_accept() != FLOW_ERR_NO)
				PUMP_ASSERT(false);
		}

		bool tcp_acceptor::__open_flow()
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			poll::channel_sptr ch = shared_from_this();
			flow_.reset(new flow::flow_tcp_acceptor());
			if (flow_->init(ch, listen_address_) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			poll::channel::__set_fd(flow_->get_fd());

			return true;
		}

	}
}
