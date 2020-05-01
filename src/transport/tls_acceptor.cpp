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

#include "pump/transport/tls_acceptor.h"
#include "pump/transport/tls_transport.h"

namespace pump {
	namespace transport {

		tls_acceptor::tls_acceptor(
			void_ptr cert, 
			const address &listen_address, 
			int64 handshake_timeout
		) : base_acceptor(TLS_ACCEPTOR, listen_address),
			cert_(cert),
			handshake_timeout_(0)
		{
		}

		bool tls_acceptor::start(service_ptr sv,const acceptor_callbacks &cbs)
		{
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.accepted_cb && cbs.stopped_cb, cbs_ = cbs);

			handshaker_cbs_.handshaked_cb = function::bind(&tls_acceptor::on_handshaked_callback,
				shared_from_this(), _1, _2);
			handshaker_cbs_.stopped_cb = function::bind(&tls_acceptor::on_stopped_handshaking_callback,
				shared_from_this(), _1);

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

		void tls_acceptor::stop()
		{
			// When in started status at the moment, stopping can be done, Then tracker event callback
			// will be triggered, we can trigger stopped callabck at there. 
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_tracker();
				__stop_all_handshakers();
			}
		}

		void tls_acceptor::on_read_event(net::iocp_task_ptr itask)
		{
			PUMP_LOCK_SPOINTER_EXPR(flow, flow_, false, 
				return);

			address local_address, remote_address;
			int32 fd = flow->accept(itask, &local_address, &remote_address);
			if (fd > 0)
			{
				tls_handshaker_ptr handshaker = __create_handshaker();
				if (handshaker)
				{
					// If handshaker is started error, handshaked callback will be triggered. So we do nothing
					// at here when started error. But if acceptor stopped befere here, we shuold stop handshaking.
					if (!handshaker->init(fd, false, cert_, local_address, remote_address))
						PUMP_ASSERT(false);
					if (handshaker->start(get_service(), handshake_timeout_, handshaker_cbs_))
					{
						if (__is_status(TRANSPORT_STOPPING) || __is_status(TRANSPORT_STOPPED))
							handshaker->stop();
					}
				}
				else
				{
					net::close(fd);
				}
			}

			// The acceptor maybe be stopped before this, so we need check it status. 
			if (flow->want_to_accept() != FLOW_ERR_NO && __is_status(TRANSPORT_STARTED))
				PUMP_ASSERT(false);
		}

		void tls_acceptor::on_handshaked_callback(
			tls_acceptor_wptr wptr,
			tls_handshaker_ptr handshaker,
			bool succ
		) {
			PUMP_LOCK_WPOINTER_EXPR(acceptor, wptr, false,
				handshaker->stop(); return);

			acceptor->__remove_handshaker(handshaker);

			if (succ && acceptor->__is_status(TRANSPORT_STARTED))
			{
				auto flow = handshaker->unlock_flow();
				address local_address = handshaker->get_local_address();
				address remote_address = handshaker->get_remote_address();
				auto transport = tls_transport::create_instance();
				if (!transport->init(flow, local_address, remote_address))
					PUMP_ASSERT(false);

				acceptor->cbs_.accepted_cb(transport);
			}			
		}

		void tls_acceptor::on_stopped_handshaking_callback(
			tls_acceptor_wptr wptr, 
			tls_handshaker_ptr handshaker
		) {
			PUMP_LOCK_WPOINTER_EXPR(acceptor, wptr, true,
				acceptor->__remove_handshaker(handshaker));
		}

		bool tls_acceptor::__open_flow()
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tls_acceptor());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, listen_address_) != FLOW_ERR_NO)
				return false;

			// Set channel FD
			channel::__set_fd(flow_->get_fd());

			return true;
		}

		tls_handshaker_ptr tls_acceptor::__create_handshaker()
		{
			tls_handshaker_sptr handshaker(new tls_handshaker);
			{
				std::lock_guard<std::mutex> lock(handshaker_mx_);
				handshakers_[handshaker.get()] = handshaker;
			}
			return handshaker.get();
		}

		void tls_acceptor::__remove_handshaker(tls_handshaker_ptr handshaker)
		{
			std::lock_guard<std::mutex> lock(handshaker_mx_);
			handshakers_.erase(handshaker);
		}

		void tls_acceptor::__stop_all_handshakers()
		{
			std::lock_guard<std::mutex> lock(handshaker_mx_);
			for (auto p: handshakers_)
				p.second->stop();
		}

	}
}