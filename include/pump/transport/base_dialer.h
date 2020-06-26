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

#ifndef pump_transport_dialer_h
#define pump_transport_dialer_h

#include "pump/transport/base_transport.h"

namespace pump {
	namespace transport {

		class LIB_PUMP base_dialer :
			public base_channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			base_dialer(
				transport_type type,
				PUMP_CONST address &local_address,
				PUMP_CONST address &remote_address,
				int64 connect_timeout
			) PUMP_NOEXCEPT : 
				base_channel(type, nullptr, -1),
				local_address_(local_address),
				remote_address_(remote_address),
				connect_timeout_(connect_timeout)
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~base_dialer()
			{ __stop_tracker(); }

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual transport_error start(
				service_ptr sv, 
				PUMP_CONST dialer_callbacks &cbs
			) = 0;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop() = 0;

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
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev) override;

		protected:
			/*********************************************************************************
			 * Start tracker
			 ********************************************************************************/
			bool __start_tracker(poll::channel_sptr &ch);

			/*********************************************************************************
			 * Stop tracker
			 ********************************************************************************/
			void __stop_tracker();

			/*********************************************************************************
			 * Start connect timer
			 ********************************************************************************/
			bool __start_connect_timer(PUMP_CONST time::timer_callback &cb);

			/*********************************************************************************
			 * Stop connect timer
			 ********************************************************************************/
			void __stop_connect_timer();

		protected:
			// Local address
			address local_address_;
			// Remote address
			address remote_address_;
			// Connect timer
			int64 connect_timeout_;
			std::shared_ptr<time::timer> connect_timer_;
			// Channel tracker
			poll::channel_tracker_sptr tracker_;
			// Dialer callbacks
			dialer_callbacks cbs_;
		};

	}
}

#endif