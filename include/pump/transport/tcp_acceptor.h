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

#include "pump/transport/base_acceptor.h"
#include "pump/transport/flow/flow_tcp_acceptor.h"

namespace pump {
	namespace transport {

		class tcp_acceptor;
		DEFINE_ALL_POINTER_TYPE(tcp_acceptor);

		class LIB_PUMP tcp_acceptor : 
			public base_acceptor,
			public std::enable_shared_from_this<tcp_acceptor>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE PUMP_STATIC tcp_acceptor_sptr create_instance(
				PUMP_CONST address &listen_address
			) {
				return tcp_acceptor_sptr(new tcp_acceptor(listen_address));
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tcp_acceptor() = default;

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual transport_error start(
				service_ptr sv, 
				PUMP_CONST acceptor_callbacks &cbs
			) override;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop() override;

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) override;

		private:
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
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tcp_acceptor(PUMP_CONST address &listen_address) PUMP_NOEXCEPT;

		private:
			// Acceptor flow
			flow::flow_tcp_acceptor_sptr flow_;
		};

	}
}

#endif
