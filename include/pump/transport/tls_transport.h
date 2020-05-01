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

#ifndef pump_transport_tls_transport_h
#define pump_transport_tls_transport_h

#include "pump/utils/features.h"
#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/base_transport.h"

#include "concurrentqueue/concurrentqueue.h"

namespace pump {
	namespace transport {

		class tls_transport;
		DEFINE_ALL_POINTER_TYPE(tls_transport);

		class LIB_EXPORT tls_transport :
			public base_transport,
			public std::enable_shared_from_this<tls_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tls_transport_sptr create_instance()
			{
				return tls_transport_sptr(new tls_transport);
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_transport();

			/*********************************************************************************
			 * Init
			 ********************************************************************************/
			bool init(
				flow::flow_tls_sptr &flow,
				const address &local_address,
				const address &remote_address
			);

			/*********************************************************************************
			 * Start tls transport
			 ********************************************************************************/
			virtual bool start(service_ptr sv, const transport_callbacks &cbs) override;

			/*********************************************************************************
			 * Stop
			 * Tls transport will delay stopping until all sendlist data is sent.
			 ********************************************************************************/
			virtual void stop() override;

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop() override;

			/*********************************************************************************
			 * Restart
			 * After paused success, this will restart transport.
			 ********************************************************************************/
			virtual bool restart() override;

			/*********************************************************************************
			 * Pause
			 ********************************************************************************/
			virtual bool pause() override;

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual bool send(
				c_block_ptr b, 
				uint32 size
			) override;

			/*********************************************************************************
			 * Send
			 * After called, the transport got the buffer onwership.
			 ********************************************************************************/
			virtual bool send(flow::buffer_ptr b) override;

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) override;

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask) override;

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_transport();

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			LIB_FORCEINLINE void __close_flow() 
			{ flow_.reset(); }

			/*********************************************************************************
			 * Async send
			 ********************************************************************************/
			bool __async_send(flow::buffer_ptr b);

			/*********************************************************************************
			 * Send once
			 * If there are no buffers to send or happening error, return 0. If sending a buffer
			 * completely, return 1. If sending a buffer not completely, return -1.
			 ********************************************************************************/
			int32 __send_once(flow::flow_tls_ptr flow);

			/*********************************************************************************
			 * Try doing transport dissconnected process
			 ********************************************************************************/
			void __try_doing_disconnected_process();

			/*********************************************************************************
			 * Clear send pockets
			 ********************************************************************************/
			void __clear_send_pockets();

		private:
			// TLS flow
			flow::flow_tls_sptr flow_;

			// When sending data, transport will append buffer to sendlist at first. On triggering send
			// event, transport will send buffer in the sendlist.
			moodycamel::ConcurrentQueue<flow::buffer_ptr> sendlist_;
			std::atomic_int32_t sendlist_size_;

			// Current send buffer
			volatile flow::buffer_ptr cur_send_buffer_;

			// Transport will start listening send event when starting. But there are maybe no data to
			// send and asynchronous sending data at the same time, so this status is for this scenario.
			std::atomic_flag is_sending_;
		};

	}
}

#endif