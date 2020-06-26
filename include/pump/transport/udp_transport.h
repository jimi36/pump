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

#ifndef pump_transport_udp_transport_h
#define pump_transport_udp_transport_h

#include "pump/transport/flow/flow_udp.h"
#include "pump/transport/base_transport.h"

namespace pump {
	namespace transport {

		class udp_transport;
		DEFINE_ALL_POINTER_TYPE(udp_transport);

		class LIB_PUMP udp_transport :
			public base_transport,
			public std::enable_shared_from_this<udp_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE PUMP_STATIC udp_transport_sptr create_instance(
				PUMP_CONST address &local_address
			) {
				return udp_transport_sptr(new udp_transport(local_address));
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~udp_transport() = default;

			/*********************************************************************************
			 * Start
			 * max_pending_send_size is ignore on udp transport.
			 ********************************************************************************/
			virtual transport_error start(
				service_ptr sv, 
				int32 max_pending_send_size,
				PUMP_CONST transport_callbacks &cbs
			) override;

			/*********************************************************************************
			 * Stop 
			 ********************************************************************************/
			virtual void stop() override;

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop() override
			{ stop(); }

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual transport_error send(
				c_block_ptr b, 
				uint32 size, 
				PUMP_CONST address &remote_address
			) override;

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) override;

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev) override;

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			udp_transport(PUMP_CONST address &local_address) PUMP_NOEXCEPT;

			/*********************************************************************************
			 * Open flow
			 ********************************************************************************/
			bool __open_flow();

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			PUMP_INLINE void __close_flow()
			{ flow_.reset(); }

			/*********************************************************************************
			 * Start read tracker
			 ********************************************************************************/
			bool __start_read_tracker();

		private:
			// Udp flow
			flow::flow_udp_sptr flow_;
		};

	}
}

#endif
