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
			STATUS_INIT = 0,
			STATUS_STARTING,
			STATUS_STARTED,
			STATUS_STOPPING,
			STATUS_STOPPED,
			STATUS_DISCONNECTING,
			STATUS_DISCONNECTED,
			STATUS_TIMEOUTING,
			STATUS_TIMEOUTED,
			STATUS_ERROR,
			STATUS_HANDSHAKING,
			STATUS_FINISHED
		};

		enum transport_type
		{
			TYPE_UDP_TRANSPORT = 0,
			TYPE_TCP_ACCEPTOR,
			TYPE_TCP_DIALER,
			TYPE_TCP_TRANSPORT,
			TYPE_TLS_ACCEPTOR,
			TYPE_TLS_DIALER,
			TYPE_TLS_HANDSHAKER,
			TYPE_TLS_TRANSPORT
		};

		enum transport_error
		{
			ERROR_OK = 0,
			ERROR_INVALID,
			ERROR_DISABLED,
			ERROR_AGAIN,
			ERROR_FAULT
		};

		class LIB_PUMP base_channel : 
			public service_getter,
			public poll::channel
		{
		public:
			/**************************************
			*******************************************
			 * Constructor
			 ********************************************************************************/
			base_channel(transport_type type, service_ptr sv, int32 fd) PUMP_NOEXCEPT :
				service_getter(sv),
				poll::channel(fd),
				tracker_cnt_(0),
				status_(STATUS_INIT),
				type_(type)
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~base_channel() = default;

			/*********************************************************************************
			 * Get transport type
			 ********************************************************************************/
			PUMP_INLINE transport_type get_type() PUMP_CONST
			{ return type_; }

			/*********************************************************************************
			 * Get started status
			 ********************************************************************************/
			PUMP_INLINE bool is_started() PUMP_CONST
			{ return __is_status(STATUS_STARTED); }

		protected:
			/*********************************************************************************
			 * Set channel status
			 ********************************************************************************/
			PUMP_INLINE bool __set_status(uint32 o, uint32 n)
			{ return status_.compare_exchange_strong(o, n); }

			/*********************************************************************************
			 * Check transport is in status
			 ********************************************************************************/
			PUMP_INLINE bool __is_status(uint32 status) PUMP_CONST
			{ return status_.load() == status; }

			/*********************************************************************************
			 * Post channel event
			 ********************************************************************************/
			PUMP_INLINE void __post_channel_event(poll::channel_sptr &ch, uint32 event)
			{ get_service()->post_channel_event(ch, event); }

		protected:
			// Tracked tracker count
			std::atomic_int16_t tracker_cnt_;
			// Channel status
			std::atomic_uint status_;
			// Channel type
			transport_type type_;
		};

		class LIB_PUMP base_transport :
			public base_channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			base_transport(transport_type type, service_ptr sv, int32 fd) :
				base_channel(type, sv, fd),
				max_pending_send_size_(-1),
				pending_send_size_(0)
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~base_transport()
			{
				__stop_read_tracker();
				__stop_send_tracker();
			}

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual transport_error start(
				service_ptr sv, 
				int32 max_pending_send_size, 
				PUMP_CONST transport_callbacks &cbs
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
			 * Send
			 ********************************************************************************/
			virtual transport_error send(c_block_ptr b, uint32 size)
			{ return ERROR_DISABLED; }

			/*********************************************************************************
			 * Send
			 * After sent success, the buffer has moved ownership to transport.
			 ********************************************************************************/
			virtual transport_error send(flow::buffer_ptr b)
			{ return ERROR_DISABLED; }

			/*********************************************************************************
			 * Send
			 ********************************************************************************/
			virtual transport_error send(
				c_block_ptr b,
				uint32 size,
				PUMP_CONST address &remote_address
			) { return ERROR_DISABLED; }

			/*********************************************************************************
			 * Get pending send buffer size
			 ********************************************************************************/
			uint32 get_pending_send_size() PUMP_CONST
			{ return pending_send_size_; }

			/*********************************************************************************
			 * Get max pending send buffer size
			 ********************************************************************************/
			uint32 get_max_pending_send_size() PUMP_CONST
			{ return max_pending_send_size_; }

			/*********************************************************************************
			 * Set max pending send buffer size
			 ********************************************************************************/
			void set_max_pending_send_size(uint32 max_size) 
			{ max_pending_send_size_ = max_size; }

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			PUMP_CONST address& get_local_address() PUMP_CONST
			{ return local_address_; }

			/*********************************************************************************
			 * Get remote address
			 ********************************************************************************/
			PUMP_CONST address& get_remote_address() PUMP_CONST
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

			// Pending send buffer size
			uint32 max_pending_send_size_;
			std::atomic_uint32_t pending_send_size_;

			// Transport callbacks
			transport_callbacks cbs_;
		};

	}
}

#endif
