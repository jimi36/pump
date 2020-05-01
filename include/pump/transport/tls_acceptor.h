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

#include "pump/transport/base_acceptor.h"
#include "pump/transport/tls_handshaker.h"
#include "pump/transport/flow/flow_tls_acceptor.h"

namespace pump {
	namespace transport {

		class tls_acceptor;
		DEFINE_ALL_POINTER_TYPE(tls_acceptor);

		class LIB_EXPORT tls_acceptor :
			public base_acceptor,
			public std::enable_shared_from_this<tls_acceptor>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tls_acceptor_sptr create_instance(
				void_ptr cert, 
				const address &listen_address, 
				int64 handshake_timeout = 0
			) {
				return tls_acceptor_sptr(new tls_acceptor(cert, listen_address, handshake_timeout));
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_acceptor() = default;

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start(service_ptr sv, const acceptor_callbacks &cbs) override;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop() override;

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) override;

		protected:
			/*********************************************************************************
			 * TLS handshaked callback
			 ********************************************************************************/
			static void on_handshaked_callback(
				tls_acceptor_wptr wptr,
				tls_handshaker_ptr handshaker,
				bool succ
			);

			/*********************************************************************************
			 * Tls handskake stopped callback
			 ********************************************************************************/
			static void on_stopped_handshaking_callback(
				tls_acceptor_wptr wptr,
				tls_handshaker_ptr handshaker
			);

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_acceptor(
				void_ptr cert, 
				const address &listen_address, 
				int64 handshake_timeout
			);

			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow();

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			LIB_FORCEINLINE void __close_flow() 
			{ flow_.reset(); }

			/*********************************************************************************
			 * Create handshaker
			 ********************************************************************************/
			tls_handshaker_ptr __create_handshaker();

			/*********************************************************************************
			 * Remove handshaker
			 ********************************************************************************/
			void __remove_handshaker(tls_handshaker_ptr handshaker);

			/*********************************************************************************
			 * Stop all handshakers
			 ********************************************************************************/
			void __stop_all_handshakers();

		private:
			// GNUTLS credentials
			void_ptr cert_;
			// GNUTLS handshake timeout time
			int64 handshake_timeout_;
			// Handshakers
			std::mutex handshaker_mx_;
			std::unordered_map<tls_handshaker_ptr, tls_handshaker_sptr> handshakers_;
			// Handshaker callbacks
			tls_handshaker::tls_handshaker_callbacks handshaker_cbs_;

			// Acceptor flow
			flow::flow_tls_acceptor_sptr flow_;
		};
	}
}

#endif