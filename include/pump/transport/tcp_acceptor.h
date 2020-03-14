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

#ifndef pump_transport_tcp_acceptor_h
#define pump_transport_tcp_acceptor_h

#include "pump/transport/tcp_transport.h"
#include "pump/transport/flow/flow_tcp_acceptor.h"

namespace pump {
	namespace transport {

		class tcp_acceptor;
		DEFINE_ALL_POINTER_TYPE(tcp_acceptor);

		class LIB_EXPORT tcp_acceptor :
			public transport_base,
			public std::enable_shared_from_this<tcp_acceptor>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tcp_acceptor_sptr create_instance()
			{
				tcp_acceptor_sptr ins(new tcp_acceptor);
				return ins;
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tcp_acceptor() {}

			/*********************************************************************************
			 * Start accepter
			 ********************************************************************************/
			bool start(
				service_ptr sv,
				const address &listen_address,
				accepted_notifier_sptr &notifier
			);

			/*********************************************************************************
			 * Stop accepter
			 ********************************************************************************/
			virtual void stop();

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(bool on);

		private:
			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow(const address &listen_address);

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

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tcp_acceptor();

		private:
			// Local address
			address listen_address_;

			// Channel tracker
			poll::channel_tracker_sptr tracker_;

			// Tcp acceptor flow
			flow::flow_tcp_acceptor_sptr flow_;
		};

	}
}

#endif
