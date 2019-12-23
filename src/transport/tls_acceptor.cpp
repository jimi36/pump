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

		tls_acceptor::~tls_acceptor()
		{
		}

		bool tls_acceptor::start(
			void_ptr tls_cert,
			service_ptr sv,
			int64 handshake_timeout,
			const address &listen_address,
			accepted_notifier_sptr &notifier
		) {
#ifdef USE_GNUTLS
			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			assert(sv);
			__set_service(sv);

			assert(tls_cert);
			__set_tls_cert(tls_cert);

			assert(notifier);
			__set_notifier(notifier);

			handshake_timeout_ = handshake_timeout;

			{
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
					assert(false);

				defer.clear();
			}

			return true;
#else
			return false;
#endif
		}

		void tls_acceptor::stop()
		{
			if (__set_status(TRANSPORT_STARTING, TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		void tls_acceptor::on_read_event(net::iocp_task_ptr itask)
		{
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (flow == nullptr)
			{
				flow::free_iocp_task(itask);
				return;
			}

			address local_address, remote_address;
			int32 fd = flow->accept(itask, &local_address, &remote_address);
			if (fd > 0)
			{
				tls_handshaker_ptr handshaker = __create_tls_handshaker();
				if (!handshaker->init(fd, false, tls_cert_, local_address, remote_address))
					assert(false);
				
				tls_handshaked_notifier_sptr notifier = shared_from_this();
				if (!handshaker->start(get_service(), handshake_timeout_, notifier))
					__remove_tls_handshaker(handshaker);
			}

			if (flow->want_to_accept() != FLOW_ERR_NO && is_started())
				assert(false);
		}

		void tls_acceptor::on_tracker_event(bool on)
		{
			if (on)
				return;

			tracker_cnt_.fetch_sub(1);

			if (tracker_cnt_ == 0)
			{
				if (!__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
					return;

				do {
					std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
					if (!tls_handshakers_.empty())
						return;
				} while (false);

				auto notifier_locker = __get_notifier<accepted_notifier>();
				auto notifier = notifier_locker.get();
				assert(notifier);

				notifier->on_stopped_accepting_callback(get_context());
			}
		}

		void tls_acceptor::on_handshaked_callback(transport_base_ptr handshaker, bool succ)
		{
			tls_handshaker_ptr the_handshaker = (tls_handshaker_ptr)handshaker;

			if (succ)
			{
				auto notifier_locker = __get_notifier<accepted_notifier>();
				auto notifier = notifier_locker.get();
				assert(notifier);

				auto flow = the_handshaker->unlock_flow();
				address local_address  = the_handshaker->get_local_address();
				address remote_address = the_handshaker->get_remote_address();
				auto transport = tls_transport::create_instance();
				if (transport->init(flow, local_address, remote_address))
					notifier->on_accepted_callback(this, transport);
			}

			__remove_tls_handshaker(the_handshaker);
		}

		void tls_acceptor::on_handshaked_timeout(transport_base_ptr handshaker)
		{
			__remove_tls_handshaker((tls_handshaker_ptr)handshaker);
		}

		void tls_acceptor::__set_tls_cert(void_ptr tls_cert)
		{
			tls_cert_ = tls_cert;
		}

		bool tls_acceptor::__open_flow(const address &listen_address)
		{
			if (flow_)
				return false;

			// Create and init flow.
			flow_.reset(new flow::flow_tls_acceptor());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, get_service()->get_iocp_handler(), listen_address) != FLOW_ERR_NO)
				return false;

			// Set channel fd.
			channel::__set_fd(flow_->get_fd());

			// Save listen address.
			listen_address_ = listen_address;

			return true;
		}

		void tls_acceptor::__close_flow()
		{
			flow_.reset();
		}

		bool tls_acceptor::__start_tracker()
		{
			if (tracker_)
				return false;

			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_KEPPING));
			tracker_->track(true);

			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tls_acceptor::__stop_tracker()
		{
			assert(tracker_);

			poll::channel_tracker_sptr tmp;
			tmp.swap(tracker_);

			get_service()->remove_channel_tracker(tmp);
		}

		tls_handshaker_ptr tls_acceptor::__create_tls_handshaker()
		{
			tls_handshaker_sptr handshaker(new tls_handshaker);
			std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
			tls_handshakers_[handshaker.get()] = handshaker;
			return handshaker.get();
		}

		void tls_acceptor::__remove_tls_handshaker(tls_handshaker_ptr handshaker)
		{
			{
				std::lock_guard<std::mutex> lock(tls_handshaker_mx_);
				tls_handshakers_.erase(handshaker);
			}

			if (__is_status(TRANSPORT_STOPPED))
			{
				auto notifier_locker = __get_notifier<accepted_notifier>();
				auto notifier = notifier_locker.get();
				assert(notifier);

				notifier->on_stopped_accepting_callback(get_context());
			}
		}

	}
}