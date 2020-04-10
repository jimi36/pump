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

		tls_acceptor::tls_acceptor():
			transport_base(TLS_ACCEPTOR, nullptr, -1),
			tls_cert_(nullptr),
			handshake_timeout_(0)
		{
		}

		bool tls_acceptor::start(
			void_ptr tls_cert,
			service_ptr sv,
			int64 handshake_timeout,
			const address &listen_address,
			accepted_notifier_sptr &notifier
		) {
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			PUMP_ASSERT_EXPR(sv, __set_service(sv));
			PUMP_ASSERT_EXPR(tls_cert, __set_tls_cert(tls_cert));
			PUMP_ASSERT_EXPR(notifier, __set_notifier(notifier));

			__set_tls_handshake_timeout(handshake_timeout);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
			});

			if (!__open_flow(listen_address))
				return false;

			if (!__start_tracker())
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
				__stop_all_tls_handshakers();
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
				tls_handshaker_ptr handshaker = __create_tls_handshaker();
				if (handshaker)
				{
					// If handshaker is started error, handshaked callback will be triggered. So we do nothing
					// at here when started error. But if acceptor stopped befere here, we shuold stop handshaking.
					if (!handshaker->init(fd, false, tls_cert_, local_address, remote_address))
						PUMP_ASSERT(false);
					tls_handshaked_notifier_sptr notifier = shared_from_this();
					if (handshaker->start(get_service(), handshake_timeout_, notifier))
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

		void tls_acceptor::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
				{
					PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<accepted_notifier>(), true,
						notifier->on_stopped_accepting_callback(get_context()));
				}
			}
		}

		void tls_acceptor::on_handshaked_callback(transport_base_ptr handshaker, bool succ)
		{
			tls_handshaker_ptr the_handshaker = (tls_handshaker_ptr)handshaker;

			if (succ && __is_status(TRANSPORT_STARTED))
			{
				auto flow = the_handshaker->unlock_flow();
				address local_address = the_handshaker->get_local_address();
				address remote_address = the_handshaker->get_remote_address();
				auto transport = tls_transport::create_instance();
				if (!transport->init(flow, local_address, remote_address))
					PUMP_ASSERT(false);

				PUMP_LOCK_SPOINTER_EXPR(notifier, __get_notifier<accepted_notifier>(), true,
					notifier->on_accepted_callback(this, transport));
			}

			__remove_tls_handshaker(the_handshaker);
		}

		void tls_acceptor::on_handshaked_timeout_callback(transport_base_ptr handshaker)
		{
			__remove_tls_handshaker((tls_handshaker_ptr)handshaker);
		}

		void tls_acceptor::on_stopped_handshaking_callback(transport_base_ptr handshaker)
		{
			__remove_tls_handshaker((tls_handshaker_ptr)handshaker);
		}

		bool tls_acceptor::__open_flow(const address &listen_address)
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tls_acceptor());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, listen_address) != FLOW_ERR_NO)
				return false;

			// Set channel FD
			channel::__set_fd(flow_->get_fd());

			// Save listen address
			listen_address_ = listen_address;

			return true;
		}

		bool tls_acceptor::__start_tracker()
		{
			PUMP_ASSERT(!tracker_);
			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tls_acceptor::__stop_tracker()
		{
			if (!tracker_)
				return;

			if (!get_service()->remove_channel_tracker(tracker_))
				PUMP_ASSERT(false);

			tracker_.reset();
		}

		tls_handshaker_ptr tls_acceptor::__create_tls_handshaker()
		{
			tls_handshaker_sptr handshaker(new tls_handshaker);
			{
				std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
				tls_handshakers_[handshaker.get()] = handshaker;
			}
			return handshaker.get();
		}

		void tls_acceptor::__remove_tls_handshaker(tls_handshaker_ptr handshaker)
		{
			std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
			tls_handshakers_.erase(handshaker);
		}

		void tls_acceptor::__stop_all_tls_handshakers()
		{
			std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
			for (auto p: tls_handshakers_)
				p.second->stop();
		}

	}
}