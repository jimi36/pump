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
#include "pump/utils/spin_mutex.h"
#include "pump/transport/flow/flow_tcp.h"
#include "pump/transport/transport_notifier.h"


namespace pump {
	namespace transport {

		class tcp_transport;
		DEFINE_ALL_POINTER_TYPE(tcp_transport);

		class LIB_EXPORT tcp_transport :
			public transport_base,
			public std::enable_shared_from_this<tcp_transport>
		{
		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			static tcp_transport_sptr create_instance()
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
			bool init(int32 fd, const address &local_address, const address &remote_address);

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool start(
				service_ptr sv, 
				transport_io_notifier_sptr &io_notifier,
				transport_terminated_notifier_sptr &terminated_notifier
			);

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop();

			/*********************************************************************************
			 * Restart
			 * After paused success, this will restart transport.
			 ********************************************************************************/
			virtual bool restart();

			/*********************************************************************************
			 * Pause
			 ********************************************************************************/
			virtual bool pause();

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual bool send(c_block_ptr b, uint32 size, bool notify = false);

			/*********************************************************************************
			 * Send
			 * After sent, the buffer has moved ownership to transport.
			 ********************************************************************************/
			virtual bool send(transport_buffer_ptr b);

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			virtual const address& get_local_address() const { return local_address_; }

			/*********************************************************************************
			 * Get remote address
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
			 * Channel event callback
			 ********************************************************************************/
			virtual void on_channel_event(uint32 event);

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			tcp_transport();

			/*********************************************************************************
			 * Set terminated notifier
			 ********************************************************************************/
			void __set_terminated_notifier(transport_terminated_notifier_sptr &notifier) 
			{ terminated_notifier_ = notifier; }

			/*********************************************************************************
			 * open flow
			 ********************************************************************************/
			bool __open_flow(int32 fd);

			/*********************************************************************************
			 * Close flow
			 ********************************************************************************/
			void __close_flow() { flow_.reset(); }

			/*********************************************************************************
			 * Start all trackers
			 ********************************************************************************/
			bool __start_all_trackers();

			/*********************************************************************************
			 * Awake tracker
			 ********************************************************************************/
			bool __awake_tracker(poll::channel_tracker_sptr tracker);

			/*********************************************************************************
			 * Pause tracker
			 ********************************************************************************/
			bool __pause_tracker(poll::channel_tracker_sptr tracker);

			/*********************************************************************************
			 * Stop tracker
			 ********************************************************************************/
			void __stop_read_tracker();
			void __stop_send_tracker();

			/*********************************************************************************
			 * Async send
			 ********************************************************************************/
			bool __async_send(transport_buffer_ptr b);
			bool __async_send(std::list<transport_buffer_ptr> &sendlist);

			/*********************************************************************************
			 * Send once
			 ********************************************************************************/
			int32 __send_once(flow::flow_tcp_ptr flow);

			/*********************************************************************************
			 * Try doing dissconnected process
			 ********************************************************************************/
			void __try_doing_disconnected_process();

			/*********************************************************************************
			 * Clear sendlist
			 ********************************************************************************/
			void __clear_sendlist();

		private:
			// Local address
			address local_address_;
			// Remote address
			address remote_address_;

			// Channel tracker
			poll::channel_tracker_sptr r_tracker_;
			poll::channel_tracker_sptr s_tracker_;

			// Transport flow
			flow::flow_tcp_sptr flow_;

			// Spin mutex used for locking sendlist
			utils::spin_mutex sendlist_mx_;
			// When sending data, tcp transport will append the data to sendlist at first. 
			// On triggering write event, the transport will send buffer in the sendlist.
			std::list<transport_buffer_ptr> sendlist_;
			
			// Tcp transport will start listening write event when starting. But there are   
			// no data to send and asynchronous sending data at the same time, so this status
			// is for this scenario.
			volatile bool ready_for_sending_;

			// Transport terminated notifier
			transport_terminated_notifier_wptr terminated_notifier_;
		};

	}
}

#endif
