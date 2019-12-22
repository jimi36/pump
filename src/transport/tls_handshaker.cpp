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

#include "librabbit/transport/tls_handshaker.h"

namespace librabbit {
	namespace transport {

		const int32 TLS_HANDSHAKE_DONE  = 0;
		const int32 TLS_HANDSHAKE_DOING = 1;
		const int32 TLS_HANDSHAKE_ERROR = 2;

		const int32 TLS_HANDSHAKE_TIMEOUT_EVENT = 0;

		tls_handshaker::tls_handshaker() :
			transport_base(TLS_HANDSHAKER, nullptr, -1)
		{
		}

		tls_handshaker::~tls_handshaker()
		{
		}

		bool tls_handshaker::init(
			int32 fd,
			bool is_client,
			void_ptr tls_cert,
			const address &local_address,
			const address &remote_address
		) {
#if defined(USE_GNUTLS)
			if (!__open_flow(fd, tls_cert, is_client))
				return false;

			local_address_  = local_address;
			remote_address_ = remote_address;

			return true;
#else
			return false;
#endif
		}

		bool tls_handshaker::start(service_ptr sv, int64 timeout, tls_handshaked_notifier_sptr &notifier)
		{
#if defined(USE_GNUTLS)
			if (!flow_)
				return false;

			if (!__set_status(TRANSPORT_INIT, TRANSPORT_STARTING))
				return false;

			assert(sv);
			__set_service(sv);

			assert(notifier);
			__set_notifier(notifier);

			if (!__start_tracker())
			{
				__set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
				return false;
			}

			__start_timer(timeout);

			if (!__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED))
				assert(false);

			return true;
#else
			return false;
#endif
		}

		void tls_handshaker::on_read_event(net::iocp_task_ptr itask)
		{
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (flow == nullptr)
			{
				flow::free_iocp_task(itask);
				return;
			}

			if (flow->recv_from_net(itask) == FLOW_ERR_ABORT)
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}
			
			switch (__process_handshake(flow))
			{
			case TLS_HANDSHAKE_DONE:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISH))
				{
					__stop_timer();
					__stop_tracker();
				}
				break;
			case TLS_HANDSHAKE_DOING:
				tracker_->track(true);
				break;
			default:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				break;
			}
		}

		void tls_handshaker::on_write_event(net::iocp_task_ptr itask)
		{
			auto flow_locker = flow_;
			auto flow = flow_locker.get();
			if (flow == nullptr)
			{
				flow::free_iocp_task(itask);
				return;
			}

			switch (flow->send_to_net(itask))
			{
			case FLOW_ERR_ABORT:
			{
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				return;
			}
			case FLOW_ERR_AGAIN:
				tracker_->track(true);
				return;
			case FLOW_ERR_NO_DATA:
				break;
			}
				
			switch (__process_handshake(flow))
			{
			case TLS_HANDSHAKE_DONE:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISH))
				{
					__stop_timer();
					__stop_tracker();
				}
				break;
			case TLS_HANDSHAKE_DOING:
				tracker_->track(true);
				break;
			default:
				if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
				{
					__stop_timer();
					__close_flow();
					__stop_tracker();
				}
				break;
			}
		}

		void tls_handshaker::on_tracker_event(bool on)
		{
			if (on)
				return;

			tracker_cnt_.fetch_sub(1);

			if (tracker_cnt_ == 0)
			{
				auto notifier_locker = __get_notifier<tls_handshaked_notifier>();
				auto notifier = notifier_locker.get();
				assert(notifier);

				if (__is_status(TRANSPORT_FINISH))
					notifier->on_handshaked_callback(this, true);
				else if (__is_status(TRANSPORT_ERROR))
					notifier->on_handshaked_callback(this, false);
				else if (__is_status(TRANSPORT_TIMEOUT))
					notifier->on_handshaked_timeout(this);
				else if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
					notifier->on_handshaked_callback(this, false);
			}
		}

		void tls_handshaker::on_timer_timeout(void_ptr arg)
		{
			if (__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUT))
			{
				__close_flow();
				__stop_tracker();
			}
		}

		bool tls_handshaker::__open_flow(int32 fd, void_ptr tls_cert, bool is_client)
		{
			// Create and init flow.
			flow_.reset(new flow::flow_tls());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, fd, tls_cert, is_client) != FLOW_ERR_NO)
				return false;

			// Set channel fd.
			poll::channel::__set_fd(fd);

			return true;
		}

		void tls_handshaker::__close_flow()
		{
			flow_.reset();
		}

		int32 tls_handshaker::__process_handshake(flow::flow_tls_ptr flow)
		{
			if (flow->handshake() != FLOW_ERR_NO)
				return TLS_HANDSHAKE_ERROR;

			if (flow->has_data_to_send())
			{
				switch (flow->want_to_send())
				{
				case FLOW_ERR_ABORT:
					return TLS_HANDSHAKE_ERROR;
				case FLOW_ERR_AGAIN:
					tracker_->set_track_event(TRACK_WRITE);
					return TLS_HANDSHAKE_DOING;
				default:
					assert(false);
				}
			}

			if (!flow->is_handshaked())
			{
				if (flow->want_to_recv() != FLOW_ERR_NO)
					return TLS_HANDSHAKE_ERROR;

				tracker_->set_track_event(TRACK_READ);
				return TLS_HANDSHAKE_DOING;
			}

			return TLS_HANDSHAKE_DONE;
		}

		void tls_handshaker::__start_timer(int64 timeout)
		{
			assert(!timer_);

			if (timeout <= 0)
				return;

			time::timeout_notifier_sptr notifier = shared_from_this();
			timer_.reset(new time::timer(nullptr, notifier, timeout));
			get_service()->start_timer(timer_);
		}

		void tls_handshaker::__stop_timer()
		{
			if (timer_)
				timer_->stop();
		}

		bool tls_handshaker::__start_tracker()
		{
			if (tracker_)
				return false;

			poll::channel_sptr ch = shared_from_this();
			tracker_.reset(new poll::channel_tracker(ch, TRACK_NONE, TRACK_MODE_ONCE));
			tracker_->track(true);

			if (__process_handshake(flow_.get()) == TLS_HANDSHAKE_ERROR)
				return false;

			if (!get_service()->add_channel_tracker(tracker_))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		bool tls_handshaker::__awake_tracker()
		{
			assert(tracker_);
			return get_service()->awake_channel_tracker(tracker_);
		}

		void tls_handshaker::__stop_tracker()
		{
			assert(tracker_);

			poll::channel_tracker_sptr tmp;
			tmp.swap(tracker_);

			get_service()->remove_channel_tracker(tmp);
		}

	}
}