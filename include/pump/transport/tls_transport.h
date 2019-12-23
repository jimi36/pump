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
#include "pump/utils/spin_mutex.h"
#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/transport_notifier.h"

namespace pump {
	namespace transport {

		class tls_transport;
		DEFINE_ALL_POINTER_TYPE(tls_transport);

		class LIB_EXPORT tls_transport :
			public transport_base,
			public std::enable_shared_from_this<tls_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tls_transport_sptr create_instance()
			{
				tls_transport_sptr ins(new tls_transport);
				return ins;
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
			bool start(
				service_ptr sv,
				transport_io_notifier_sptr &io_notifier,
				transport_terminated_notifier_sptr &terminated_notifier
			);

			/*********************************************************************************
			 * Stop
			 * Tls transport will delay stopping until all sendlist data is sent.
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop();

			/*********************************************************************************
			 * Send
			 * This is a asynchronous operation. If notify is set to true, transport will 
			 * notify when the data is sent completely.
			 ********************************************************************************/
			virtual bool send(c_block_ptr b, uint32 size, bool notify = false);

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			const address& get_local_address() const { return local_address_; }

			/*********************************************************************************
			 * Get peer address
			 ********************************************************************************/
			const address& get_remote_address() const { return remote_address_; }

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Write event callback
			 ********************************************************************************/
			virtual void on_write_event(net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(bool on);

			/*********************************************************************************
			 * Channel event callback
			 ********************************************************************************/
			virtual void on_channel_event(uint32 event);

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tls_transport();

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			void __close_flow();

			/*********************************************************************************
			 * Start all trackers
			 ********************************************************************************/
			bool __start_all_trackers();

			/*********************************************************************************
			 * Awake tracker
			 ********************************************************************************/
			bool __awake_tracker(poll::channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Stop write tracker
			 ********************************************************************************/
			void __stop_tracker(poll::channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Async write
			 ********************************************************************************/
			bool __async_write(std::list<flow::buffer_ptr> &sendlist, bool notify);

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
			// Local address
			address local_address_;

			// Remote address
			address remote_address_;

			// Channel tracker
			poll::channel_tracker_sptr r_tracker_;
			poll::channel_tracker_sptr s_tracker_;

			// Tls flow layer
			flow::flow_tls_sptr flow_;

			// The spin mutex is used for protecting sendlist in multithreading. We use spin
			// mutex because it's more efficient than other mutex in frequently invoked scenarios.
			utils::spin_mutex sendlist_mx_;

			// When Using tcp transport asynchronous send data, tcp transport will append
			// data to sendlist at first. And when write event is triggered, tcp transport 
			// will get data from sendlist to send.
			std::list<flow::buffer_ptr> sendlist_;

			// When write data with complteted_notify as true, transport will store the last
			// buffer of buffer list that split from data to this buffer list. When buffer
			// in the list is sent completed, transport will call send_completed callback.
			std::vector<void_ptr> sent_notify_list_;

			// Tcp transport will start listening write event when starting. But there is no 
			// data to send and maybe there is data asynchronous sending at the same time, so
			// this status is for this scenario.
			volatile bool ready_for_sending_;

			// Transport terminated notifier
			transport_terminated_notifier_wptr terminated_notifier_;
		};

	}
}

#endif