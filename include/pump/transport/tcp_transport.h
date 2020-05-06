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

#ifndef pump_transport_tcp_transport_h
#define pump_transport_tcp_transport_h

#include "pump/utils/features.h"
#include "pump/transport/flow/flow_tcp.h"
#include "pump/transport/base_transport.h"

#include "concurrentqueue/concurrentqueue.h"

namespace pump {
	namespace transport {

		class tcp_transport;
		DEFINE_ALL_POINTER_TYPE(tcp_transport);

		class LIB_PUMP tcp_transport : 
			public base_transport,
			public std::enable_shared_from_this<tcp_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE PUMP_STATIC tcp_transport_sptr create_instance()
			{
				return tcp_transport_sptr(new tcp_transport);
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tcp_transport();

			/*********************************************************************************
			 * Init
			 ********************************************************************************/
			bool init(
				int32 fd, 
				PUMP_CONST address &local_address, 
				PUMP_CONST address &remote_address
			);

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start(service_ptr sv, PUMP_CONST transport_callbacks &cbs) override;

			/*********************************************************************************
			 * Stop
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
			virtual bool send(c_block_ptr b, uint32 size) override;

			/*********************************************************************************
			 * Send
			 * After sent success, the buffer has moved ownership to transport.
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
			tcp_transport() PUMP_NOEXCEPT;

			/*********************************************************************************
			 * open flow
			 ********************************************************************************/
			bool __open_flow(int32 fd);

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			PUMP_INLINE void __close_flow()
			{ if (flow_) flow_->close(); }

			/*********************************************************************************
			 * Async send
			 ********************************************************************************/
			bool __async_send(flow::buffer_ptr b);

			/*********************************************************************************
			 * Send once
			 ********************************************************************************/
			bool __send_once(flow::flow_tcp_ptr flow);

			/*********************************************************************************
			 * Try doing dissconnected process
			 ********************************************************************************/
			void __try_doing_disconnected_process();

			/*********************************************************************************
			 * Clear sendlist
			 ********************************************************************************/
			void __clear_sendlist();

		private:
			// Transport flow
			flow::flow_tcp_sptr flow_;

			// When sending data, transport will append buffer to sendlist at first. On triggering send
			// event, transport will send buffer in the sendlist.
			moodycamel::ConcurrentQueue<flow::buffer_ptr> sendlist_;
			std::atomic_int32_t sendlist_size_;
			
			// Last send buffer
			volatile flow::buffer_ptr last_send_buffer_;

			// Who got next send chance, who can send next buffer.
			std::atomic_flag next_send_chance_;
		};

	}
}

#endif
