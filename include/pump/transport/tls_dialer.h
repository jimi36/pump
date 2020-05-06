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

#ifndef pump_transport_tls_dialer_h
#define pump_transport_tls_dialer_h

#include "pump/transport/base_dialer.h"
#include "pump/transport/tls_handshaker.h"
#include "pump/transport/flow/flow_tls_dialer.h"

namespace pump {
	namespace transport {

		class tls_dialer;
		DEFINE_ALL_POINTER_TYPE(tls_dialer);

		class LIB_PUMP tls_dialer : 
			public base_dialer,
			public std::enable_shared_from_this<tls_dialer>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE PUMP_STATIC tls_dialer_sptr create_instance(
				void_ptr cert,
				PUMP_CONST address &local_address,
				PUMP_CONST address &remote_address,
				int64 dial_timeout = 0,
				int64 handshake_timeout = 0
			) {
				return tls_dialer_sptr(new tls_dialer(
					cert,
					local_address, 
					remote_address, 
					dial_timeout, 
					handshake_timeout
				));
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_dialer() = default;

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start(service_ptr sv, PUMP_CONST dialer_callbacks &cbs) override;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop() override;

		protected:
			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask) override;

		protected:
			/*********************************************************************************
			 * Timeout event callback
			 ********************************************************************************/
			PUMP_STATIC void on_timeout(tls_dialer_wptr wptr);

			/*********************************************************************************
			 * TLS handshake success callback
			 ********************************************************************************/
			PUMP_STATIC void on_handshaked_callback(
				tls_dialer_wptr wptr,
				tls_handshaker_ptr handshaker,
				bool succ
			);

			/*********************************************************************************
			 * Tls handskake stopped callback
			 ********************************************************************************/
			PUMP_STATIC void on_handshake_stopped_callback(
				tls_dialer_wptr wptr,
				tls_handshaker_ptr handshaker
			);

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_dialer(
				void_ptr cert,
				PUMP_CONST address &local_address,
				PUMP_CONST address &remote_address,
				int64 dial_timeout,
				int64 handshake_timeout
			) PUMP_NOEXCEPT;

			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow();

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			PUMP_INLINE void __close_flow()
			{ if (flow_) flow_->close(); }

		private:
			// GNUTLS credentials
			void_ptr cert_;
			// Dialer flow
			flow::flow_tls_dialer_sptr flow_;
			// Handshake timeout
			int64 handshake_timeout_;
			// Handshaker
			tls_handshaker_sptr handshaker_;
		};

		class tls_sync_dialer;
		DEFINE_ALL_POINTER_TYPE(tls_sync_dialer);

		class LIB_PUMP tls_sync_dialer :
			public std::enable_shared_from_this<tls_sync_dialer>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_STATIC tls_sync_dialer_sptr create_instance()
			{
				return tls_sync_dialer_sptr(new tls_sync_dialer);
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_sync_dialer() = default;

			/*********************************************************************************
			 * Dial by sync
			 ********************************************************************************/
			base_transport_sptr dial(
				void_ptr cert,
				service_ptr sv,
				PUMP_CONST address &local_address,
				PUMP_CONST address &remote_address,
				int64 connect_timeout,
				int64 handshake_timeout
			);

		protected:
			/*********************************************************************************
			 * Dialed event callback
			 ********************************************************************************/
			PUMP_STATIC void on_dialed_callback(
				tls_sync_dialer_wptr wptr,
				base_transport_sptr transp,
				bool succ
			);

			/*********************************************************************************
			 * Dialed timeout event callback
			 ********************************************************************************/
			PUMP_STATIC void on_timeout_callback(tls_sync_dialer_wptr wptr);

			/*********************************************************************************
			 * Stopped dial event callback
			 ********************************************************************************/
			PUMP_STATIC void on_stopped_callback();

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_sync_dialer() PUMP_NOEXCEPT
			{}

			/*********************************************************************************
			 * Reset sync dialer
			 ********************************************************************************/
			PUMP_INLINE void __reset()
			{ dialer_.reset(); }

		private:
			// Tcp dialer
			tls_dialer_sptr dialer_;
			// Dial promise
			std::promise<base_transport_sptr> dial_promise_;
		};

	}
}

#endif