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

#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/base_transport.h"

namespace pump {
	namespace transport {

		class tls_transport;
		DEFINE_ALL_POINTER_TYPE(tls_transport);

		class LIB_PUMP tls_transport : 
			public base_transport,
			public std::enable_shared_from_this<tls_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE static tls_transport_sptr create_instance()
			{
				INLINE_OBJECT_CREATE(
					obj, 
					tls_transport, 
					()
				);
				return tls_transport_sptr(obj, object_delete<tls_transport>);
			}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~tls_transport();

			/*********************************************************************************
			 * Init
			 ********************************************************************************/
			void init(
				flow::flow_tls_sptr &flow,
				const address &local_address,
				const address &remote_address
			);

			/*********************************************************************************
			 * Start tls transport
			 ********************************************************************************/
			virtual transport_error start(
				service_ptr sv,
				int32 max_pending_send_size,
				const transport_callbacks &cbs
			) override;

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
			 * Send
			 ********************************************************************************/
			virtual transport_error send(c_block_ptr b, uint32 size) override;

		protected:
			/*********************************************************************************
			 * Channel event callback
			 ********************************************************************************/
			virtual void on_channel_event(uint32 ev) override;

			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(void_ptr iocp_task) override;

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(void_ptr iocp_task) override;

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_transport() noexcept;

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
			bool __send_once(flow::flow_tls_ptr flow);

			/*********************************************************************************
			 * Read tls data
			 ********************************************************************************/
			void __read_tls_data(flow::flow_tls_ptr flow);

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

			// Last send buffer
			volatile uint32 last_send_buffer_size_;
			volatile flow::buffer_ptr last_send_buffer_;

			// When sending data, transport will append buffer to sendlist at first. On triggering send
			// event, transport will send buffer in the sendlist.
			moodycamel::ConcurrentQueue<flow::buffer_ptr> sendlist_;

			// Who got next send chance, who can send next buffer.
			std::atomic_flag next_send_chance_;
		};

	}
}

#endif