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
#include "pump/transport/transport_notifier.h"

namespace pump {
	namespace transport {

		class tls_handshaked_notifier
		{
		public:
			/*********************************************************************************
			 * Tls handskake success callback
			 ********************************************************************************/
			virtual void on_handshaked_callback(transport_base_ptr handshaker, bool succ) = 0;

			/*********************************************************************************
			 * Tls handskake timeout callback
			 ********************************************************************************/
			virtual void on_handshaked_timeout_callback(transport_base_ptr handshaker) = 0;

			/*********************************************************************************
			 * Tls handskake stopped callback
			 ********************************************************************************/
			virtual void on_stopped_handshaking_callback(transport_base_ptr handshaker) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(tls_handshaked_notifier);

		class tls_handshaker :
			public transport_base,
			public time::timeout_notifier,
			public std::enable_shared_from_this<tls_handshaker>
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_handshaker();

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_handshaker() {}

			/*********************************************************************************
			 * Init
			 ********************************************************************************/
			bool init(
				int32 fd,
				bool is_client,
				void_ptr tls_cert,
				const address &local_address,
				const address &remote_address
			);

			/*********************************************************************************
			 * Start tls handshaker
			 ********************************************************************************/
			bool start(
				service_ptr sv, 
				int64 timeout, 
				tls_handshaked_notifier_sptr &notifier
			);
			bool start(
				service_ptr sv, 
				poll::channel_tracker_sptr &tracker, 
				int64 timeout, 
				tls_handshaked_notifier_sptr &notifier
			);

			/*********************************************************************************
			 * Stop transport
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Unlock flow
			 ********************************************************************************/
			LIB_FORCEINLINE flow::flow_tls_sptr unlock_flow() 
			{ return std::move(flow_); }

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			virtual const address& get_local_address() const { return local_address_; }

			/*********************************************************************************
			 * Start remote address
			 ********************************************************************************/
			virtual const address& get_remote_address() const { return remote_address_; }

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev);

			/*********************************************************************************
			 * Timer timeout callback
			 ********************************************************************************/
			virtual void on_timer_timeout(void_ptr arg);

		private:
			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow(int32 fd, void_ptr tls_cert, bool is_client);

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			LIB_FORCEINLINE void __close_flow() 
			{ flow_.reset(); }

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
			// Tls flow
			flow::flow_tls_sptr flow_;
		};
		DEFINE_ALL_POINTER_TYPE(tls_handshaker);

	}
}

#endif