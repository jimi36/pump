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

#ifndef pump_transport_channel_h
#define pump_transport_channel_h

#include "pump/service.h"
#include "pump/poll/channel.h"
#include "pump/transport/address.h"
#include "pump/transport/callbacks.h"
#include "pump/transport/flow/buffer.h"

namespace pump {
	namespace transport {

		namespace flow {
			class flow_base;
		}

		/*********************************************************************************
		 * Transport status
		 ********************************************************************************/
		enum transport_status
		{
			TRANSPORT_INIT      = 0,
			TRANSPORT_STARTING,
			TRANSPORT_STARTED,
			TRANSPORT_PAUSED,
			TRANSPORT_STOPPING,
			TRANSPORT_STOPPED,
			TRANSPORT_DISCONNECTING,
			TRANSPORT_DISCONNECTED,
			TRANSPORT_TIMEOUT_DOING,
			TRANSPORT_TIMEOUT_DONE,
			TRANSPORT_ERROR,
			TRANSPORT_HANDSHAKING,
			TRANSPORT_FINISH
		};

		enum transport_type
		{
			UDP_TRANSPORT = 0,
			TCP_ACCEPTOR,
			TCP_DIALER,
			TCP_TRANSPORT,
			TLS_ACCEPTOR,
			TLS_DIALER,
			TLS_HANDSHAKER,
			TLS_TRANSPORT
		};

		class LIB_EXPORT base_channel:
			public service_getter,
			public poll::channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			base_channel(transport_type type, service_ptr sv, int32 fd) :
				service_getter(sv),
				poll::channel(fd),
				tracker_cnt_(0),
				status_(TRANSPORT_INIT),
				type_(type) 
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~base_channel() = default;

			/*********************************************************************************
			 * Get transport type
			 ********************************************************************************/
			LIB_FORCEINLINE transport_type get_type() const 
			{ return type_; }

			/*********************************************************************************
			 * Get started status
			 ********************************************************************************/
			LIB_FORCEINLINE bool is_started() 
			{ return __is_status(TRANSPORT_STARTED); }

		protected:
			/*********************************************************************************
			 * Set channel status
			 ********************************************************************************/
			LIB_FORCEINLINE bool __set_status(uint32 o, uint32 n)
			{ return status_.compare_exchange_strong(o, n); }

			/*********************************************************************************
			 * Check transport is in status
			 ********************************************************************************/
			LIB_FORCEINLINE bool __is_status(uint32 status) 
			{ return status_.load() == status; }

			/*********************************************************************************
			 * Post channel event
			 ********************************************************************************/
			LIB_FORCEINLINE void __post_channel_event(poll::channel_sptr &ch, uint32 event)
			{ get_service()->post_channel_event(ch, event); }

		protected:
			// Tracked tracker count
			std::atomic_int16_t tracker_cnt_;
			// Channel status
			std::atomic_uint status_;
			// Channel type
			transport_type type_;
		};

		class LIB_EXPORT base_transport :
			public base_channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			base_transport(transport_type type, service_ptr sv, int32 fd) :
				base_channel(type, sv, fd)
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~base_transport() = default;

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start(
				service_ptr sv,
				const transport_callbacks &cbs
			) = 0;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop() = 0;

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop() = 0;

			/*********************************************************************************
			 * Restart
			 * After paused success, this will restart transport.
			 ********************************************************************************/
			virtual bool restart() 
			{ return false; }

			/*********************************************************************************
			 * Pause
			 ********************************************************************************/
			virtual bool pause() 
			{ return false; }

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual bool send(c_block_ptr b, uint32 size)
			{ return false; }

			/*********************************************************************************
			 * Send
			 * After sent, the buffer has moved ownership to transport.
			 ********************************************************************************/
			virtual bool send(flow::buffer_ptr b)
			{ return false; }

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual bool send(
				c_block_ptr b,
				uint32 size,
				const address &remote_address
			) { return false; }

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			const address& get_local_address() const
			{ return local_address_; }

			/*********************************************************************************
			 * Get remote address
			 ********************************************************************************/
			const address& get_remote_address() const
			{ return remote_address_; }

		protected:
			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev) override;

		protected:
			/*********************************************************************************
			 * Start all trackers
			 ********************************************************************************/
			bool __start_all_trackers(poll::channel_sptr &ch);

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

		protected:
			// Local address
			address local_address_;
			// Remote address
			address remote_address_;

			// Channel trackers
			poll::channel_tracker_sptr r_tracker_;
			poll::channel_tracker_sptr s_tracker_;

			// Transport callbacks
			transport_callbacks cbs_;
		};

	}
}

#endif
