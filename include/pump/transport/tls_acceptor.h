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

#ifndef pump_transport_tls_acceptor_h
#define pump_transport_tls_acceptor_h

#include "pump/transport/tls_handshaker.h"
#include "pump/transport/flow/flow_tls_acceptor.h"

namespace pump {
	namespace transport {

		class tls_acceptor;
		DEFINE_ALL_POINTER_TYPE(tls_acceptor);

		class LIB_EXPORT tls_acceptor :
			public transport_base,
			public tls_handshaked_notifier,
			public std::enable_shared_from_this<tls_acceptor>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tls_acceptor_sptr create_instance()
			{
				tls_acceptor_sptr ins(new tls_acceptor);
				return ins;
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_acceptor() {}

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool start(
				void_ptr tls_cert,
				service_ptr sv,
				int64 handshake_timeout,
				const address &listen_address,
				accepted_notifier_sptr &notifier
			);

			/*********************************************************************************
			 * Stop
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

			/*********************************************************************************
			 * Tls handshake success callback
			 ********************************************************************************/
			virtual void on_handshaked_callback(transport_base_ptr handshaker, bool succ);

			/*********************************************************************************
			 * Tls handshake timeout callback
			 ********************************************************************************/
			virtual void on_handshaked_timeout(transport_base_ptr handshaker);

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_acceptor();

			/*********************************************************************************
			 * Set tls credentials
			 ********************************************************************************/
			void __set_tls_cert(void_ptr tls_cert) { tls_cert_ = tls_cert; }

			/*********************************************************************************
			 * Set tls handshake timeout
			 ********************************************************************************/
			void __set_tls_handshake_timeout(int64 timeout) { handshake_timeout_ = timeout; }

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

			/*********************************************************************************
			 * Create tls handshaker
			 ********************************************************************************/
			tls_handshaker_ptr __create_tls_handshaker();

			/*********************************************************************************
			 * Remove tls handshaker
			 ********************************************************************************/
			void __remove_tls_handshaker(tls_handshaker_ptr handshaker);

		private:
			// GNUTls credentials
			void_ptr tls_cert_;
			// Listen address
			address listen_address_;
			// Channel tracker
			poll::channel_tracker_sptr tracker_;
			// Tls acceptor flow layer
			flow::flow_tls_acceptor_sptr flow_;
			// GNUTls handshake info
			int64 handshake_timeout_;
			std::mutex tls_handshaker_mx_;
			std::unordered_map<tls_handshaker_ptr, tls_handshaker_sptr> tls_handshakers_;
		};
	}
}

#endif