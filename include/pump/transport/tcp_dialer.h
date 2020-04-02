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

#ifndef pump_transport_tcp_dialer_h
#define pump_transport_tcp_dialer_h

#include "pump/time/timer.h"
#include "pump/transport/tcp_transport.h"
#include "pump/transport/flow/flow_tcp_dialer.h"

namespace pump {
	namespace transport {

		class tcp_dialer;
		DEFINE_ALL_POINTER_TYPE(tcp_dialer);

		class LIB_EXPORT tcp_dialer :
			public transport_base,
			public time::timeout_notifier,
			public std::enable_shared_from_this<tcp_dialer>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tcp_dialer_sptr create_instance()
			{
				return tcp_dialer_sptr(new tcp_dialer);
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tcp_dialer() {}

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool start(
				service_ptr sv,
				int64 timeout,
				const address &bind_address,
				const address &connect_address,
				dialed_notifier_sptr &notifier
			);

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			virtual const address& get_local_address() const { return bind_address_; }

			/*********************************************************************************
			 * Get remote address
			 ********************************************************************************/
			virtual const address& get_remote_address() const { return peer_address_; }

		protected:
			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev);

			/*********************************************************************************
			 * Timeout event callback
			 ********************************************************************************/
			virtual void on_timer_timeout(void_ptr arg);

		private:
			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow(const address &bind_address);

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			void __close_flow() { flow_.reset(); }

			/*********************************************************************************
			 * Start tracker
			 ********************************************************************************/
			bool __start_tracker();

			/*********************************************************************************
			 * Stop tracker
			 ********************************************************************************/
			void __stop_tracker();

			/*********************************************************************************
			 * Start timeout timer
			 ********************************************************************************/
			bool __start_timer(int64 timeout);

			/*********************************************************************************
			 * Stop timeout timer
			 ********************************************************************************/
			void __stop_timer();

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tcp_dialer();

		private:
			// Bind address
			address bind_address_;
			// Peer address
			address peer_address_;
			// Connect timer
			std::shared_ptr<time::timer> timer_;
			// Channel tracker
			poll::channel_tracker_sptr tracker_;
			// Dialer flow
			flow::flow_tcp_dialer_sptr flow_;
		};

	}
}

#endif
