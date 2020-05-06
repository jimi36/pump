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

#ifndef pump_transport_tls_handshaker_h
#define pump_transport_tls_handshaker_h

#include "pump/time/timer.h"
#include "pump/utils/features.h"
#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/base_transport.h"

namespace pump {
	namespace transport {

		class tls_handshaker;
		DEFINE_ALL_POINTER_TYPE(tls_handshaker);

		class tls_handshaker : 
			public base_channel,
			public std::enable_shared_from_this<tls_handshaker>
		{
		public:
			struct tls_handshaker_callbacks
			{
				function::function<
					void(tls_handshaker_ptr, bool)
				> handshaked_cb;

				function::function<
					void(tls_handshaker_ptr)
				> stopped_cb;
			};

		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_handshaker() PUMP_NOEXCEPT;

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_handshaker() = default;

			/*********************************************************************************
			 * Init
			 ********************************************************************************/
			bool init(
				int32 fd,
				bool is_client,
				void_ptr tls_cert,
				PUMP_CONST address &local_address,
				PUMP_CONST address &remote_address
			);

			/*********************************************************************************
			 * Start tls handshaker
			 ********************************************************************************/
			bool start(
				service_ptr sv, 
				int64 timeout, 
				PUMP_CONST tls_handshaker_callbacks &cbs
			);
			bool start(
				service_ptr sv, 
				poll::channel_tracker_sptr &tracker, 
				int64 timeout, 
				PUMP_CONST tls_handshaker_callbacks &cbs
			);

			/*********************************************************************************
			 * Stop transport
			 ********************************************************************************/
			void stop();

			/*********************************************************************************
			 * Unlock flow
			 ********************************************************************************/
			PUMP_INLINE flow::flow_tls_sptr unlock_flow()
			{ return std::move(flow_); }

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			PUMP_INLINE PUMP_CONST address& get_local_address() PUMP_CONST
			{ return local_address_; }

			/*********************************************************************************
			 * Get remote address
			 ********************************************************************************/
			PUMP_INLINE PUMP_CONST address& get_remote_address() PUMP_CONST
			{ return remote_address_; }

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) override;

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask) override;

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev) override;

		protected:
			/*********************************************************************************
			 * Timer timeout callback
			 ********************************************************************************/
			PUMP_STATIC void on_timeout(tls_handshaker_wptr wptr);

		private:
			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow(int32 fd, void_ptr tls_cert, bool is_client);

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			PUMP_INLINE void __close_flow()
			{ if (flow_) flow_->close(); }

			/*********************************************************************************
			 * Process handshake
			 ********************************************************************************/
			int32 __process_handshake(
				flow::flow_tls_ptr flow, 
				poll::channel_tracker_ptr tracker
			);

			/*********************************************************************************
			 * Start handshaking timer
			 ********************************************************************************/
			bool __start_timer(int64 timeout);

			/*********************************************************************************
			 * Stop handshaking timer
			 ********************************************************************************/
			void __stop_timer();

			/*********************************************************************************
			 * Start tracker
			 * This will create new tracker and start it.
			 ********************************************************************************/
			bool __start_tracker();

			/*********************************************************************************
			 * Start tracker
			 * This will use the specified tracker and awake it.
			 ********************************************************************************/
			bool __restart_tracker(poll::channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Stop tracker
			 ********************************************************************************/
			void __stop_tracker();

			/*********************************************************************************
			 * Awake tracker
			 ********************************************************************************/
			void __awake_tracker(poll::channel_tracker_ptr tracker);

		private:
			// Local address
			address local_address_;
			// Remote address
			address remote_address_;
			// Finished flag
			std::atomic_flag flag_;
			// Handshake timeout timer
			time::timer_sptr timer_;
			// Channel tracker
			poll::channel_tracker_sptr tracker_;
			// TLS flow
			flow::flow_tls_sptr flow_;
			// TLS handshaker callbacks
			tls_handshaker_callbacks cbs_;
		};

	}
}

#endif