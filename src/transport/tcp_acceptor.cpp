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

		tcp_acceptor::tcp_acceptor(const address &listen_address) :
			base_acceptor(TCP_ACCEPTOR, listen_address)
		{}

		bool tcp_acceptor::start(service_ptr sv,const acceptor_callbacks &cbs)
		{
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.accepted_cb && cbs.stopped_cb, cbs_ = cbs);	

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__open_flow())
				return false;

			if (!__start_tracker((poll::channel_sptr)shared_from_this()))
				return false;

			if (flow_->want_to_accept() != FLOW_ERR_NO)
				return false;

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				PUMP_ASSERT(false);

			defer.clear();

			return true;
		}

		void tcp_acceptor::stop()
		{
			// When in started status at the moment, stopping can be done. Then tracker
			// event callback will be triggered, we can trigger stopped callabck at there.
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		void tcp_acceptor::on_read_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false, 
				return);

			address local_address, remote_address;
			int32 fd = flow->accept(itask, &local_address, &remote_address);
			if (fd > 0)
			{
				auto conn = tcp_transport::create_instance();
				if (!conn->init(fd, local_address, remote_address))
					PUMP_ASSERT(false);

				// The acceptor maybe be stopped before this, so we need check it in started 
				// status or not. And if notifier is already not existed, we only can close the
				// new tcp connection.
				if (__is_status(TRANSPORT_STARTED))
					cbs_.accepted_cb(conn);
			}

			// The acceptor maybe be stopped before this, so we also need check it in started 
			// status or not.
			if (flow->want_to_accept() != FLOW_ERR_NO && __is_status(TRANSPORT_STARTED))
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

			// Set channel FD
			poll::channel::__set_fd(flow_->get_fd());

			return true;
		}

	}
}