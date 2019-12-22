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

#include "librabbit/transport/tls_dialer.h"
#include "librabbit/transport/tls_transport.h"

namespace librabbit {
	namespace transport {

		tls_dialer::tls_dialer() :
			transport_base(TLS_DIALER, nullptr, -1),
			tls_cert_(nullptr),
			handshake_timeout_(0)
		{
		}

		tls_dialer::~tls_dialer()
		{
		}

		bool tls_dialer::start(
			void_ptr tls_cert,
			service_ptr sv,
			int64 connect_timeout,
			int64 handshake_timeout,
			const address &bind_address,
			const address &connect_address,
			dialed_notifier_sptr &notifier
		) {
#if defined(USE_GNUTLS)
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

				if (!__open_flow(bind_address))
					return false;

				if (!__start_tracker())
					return false;

				if (flow_->want_to_connect(connect_address) != FLOW_ERR_NO)
					return false;

				__start_timer(connect_timeout);

				if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
					assert(false);

				defer.clear();
			}

			return true;
#else
			return false;
#endif
		}

		void tls_dialer::stop()
		{
#if defined(USE_GNUTLS)
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING))
			{
				__close_flow();
				__stop_timer();
				__stop_tracker();
			}
#endif
		}

		void tls_dialer::on_write_event(net::iocp_task_ptr itask)
		{
			if (!__set_status(TRANSPORT_STARTED, TRANSPORT_HANDSHAKING))
			{
				flow::free_iocp_task(itask);
				return;
			}

			utils::scoped_defer defer([&]() {
				__stop_timer();
				__close_flow();
				__stop_tracker();
			});
			
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (flow == nullptr)
			{
				flow::free_iocp_task(itask);
				return;
			}

			address local_address, remote_address;
			int32 code = flow->connect(itask, local_address, remote_address);
			if (code == 0)
			{
				int32 fd = flow->get_and_unlock_fd();
				
				tls_handshaker_sptr handshaker(new tls_handshaker);
				tls_handshaked_notifier_sptr notifier = shared_from_this();
				if (!handshaker->init(fd, true, tls_cert_, local_address, remote_address))
					assert(false);

				if (!handshaker->start(get_service(), handshake_timeout_, std::move(notifier)))
				{
					__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR);
					return;
				}

				handshaker_ = handshaker;				
			}
			else
			{
				__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR);
			}
		}

		void tls_dialer::on_tracker_event(bool on)
		{
			if (on)
				return;

			tracker_cnt_.fetch_sub(1);

			if (tracker_cnt_ == 0)
			{
				auto notifier_locker = __get_notifier<dialed_notifier>();
				auto notifier = notifier_locker.get();
				assert(notifier);
				
				if (__is_status(TRANSPORT_ERROR))
					notifier->on_dialed_callback(get_context(), tls_transport_sptr(), false);
				else if (__is_status(TRANSPORT_TIMEOUT))
					notifier->on_dialed_timeout_callback(get_context());
			}
		}

		void tls_dialer::on_timer_timeout(void_ptr arg)
		{
			if (__set_status(TRANSPORT_STARTING, TRANSPORT_TIMEOUT))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		void tls_dialer::on_handshaked_callback(transport_base_ptr handshaker, bool succ)
		{
			if (!__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_FINISH))
				return;

			handshaker_.reset();

			auto notifier_locker = __get_notifier<dialed_notifier>();
			auto notifier = notifier_locker.get();
			assert(notifier);

			auto the_handshaker = (tls_handshaker_ptr)handshaker;
			auto flow = the_handshaker->unlock_flow();
			auto transp = tls_transport::create_instance();
			if (transp->init(flow, the_handshaker->get_local_address(), the_handshaker->get_remote_address()))
				notifier->on_dialed_callback(get_context(), transp, true);
		}

		void tls_dialer::on_handshaked_timeout(transport_base_ptr handshaker)
		{
			if (!__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_TIMEOUT))
				return;

			handshaker_.reset();

			auto notifier_locker = __get_notifier<dialed_notifier>();
			auto notifier = notifier_locker.get();
			assert(notifier);

			notifier->on_dialed_timeout_callback(get_context());
		}

		void tls_dialer::__set_tls_cert(void_ptr tls_cert)
		{
			tls_cert_ = tls_cert;
		}

		bool tls_dialer::__open_flow(const address &bind_address)
		{
			if (flow_)
				return false;

			// Create and init flow.
			flow_.reset(new flow::flow_tcp_dialer());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, get_service()->get_iocp_handler(), bind_address) != FLOW_ERR_NO)
				return false;

			// Set channel fd.
			poll::channel::__set_fd(flow_->get_fd());

			// Save bind address.
			bind_address_ = bind_address;

			return true;
		}

		void tls_dialer::__close_flow()
		{
			flow_.reset();
		}

		bool tls_dialer::__start_tracker()
		{
			if (tracker_)
				return false;

			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(std::move(ch), TRACK_WRITE, TRACK_MODE_ONCE));
			tracker_->track(true);

			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void tls_dialer::__stop_tracker()
		{
			if (!tracker_)
				return;

			poll::channel_tracker_sptr tmp;
			tmp.swap(tracker_);

			get_service()->remove_channel_tracker(tmp);
		}

		void tls_dialer::__start_timer(int64 timeout)
		{
			assert(!timer_);

			if (timeout <= 0)
				return;

			time::timeout_notifier_sptr notifier = shared_from_this();
			timer_.reset(new time::timer(nullptr, notifier, timeout));
			get_service()->start_timer(timer_);
		}

		void tls_dialer::__stop_timer()
		{
			if (timer_)
				timer_->stop();
		}

	}
}
