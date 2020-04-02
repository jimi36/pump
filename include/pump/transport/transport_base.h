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

		enum transport_event 
		{
			TRANSPORT_SENT_EVENT = 0
		};

		class LIB_EXPORT transport_buffer:
			public flow::buffer 
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			transport_buffer():
				completed_notify_(false)
			{}

			/*********************************************************************************
			 * Set completed notify status
			 ********************************************************************************/
			void set_completed_notify(bool notify) { completed_notify_ = notify; }

			/*********************************************************************************
			 * Check completed notify status
			 ********************************************************************************/
			bool need_completed_notify() const { return completed_notify_; }

		private:
			bool completed_notify_;
		};
		DEFINE_ALL_POINTER_TYPE(transport_buffer);

		class LIB_EXPORT transport_base:
			public service_getter,
			public poll::channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			transport_base(transport_type type, service_ptr sv = nullptr, int32 fd = -1):
				service_getter(sv),
				poll::channel(fd),
				tracker_cnt_(0),
				status_(TRANSPORT_INIT),
				type_(type) {}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~transport_base() {}

			/*********************************************************************************
			 * Stop channel
			 ********************************************************************************/
			virtual void stop() {}

			/*********************************************************************************
			 * Force stop
			 ********************************************************************************/
			virtual void force_stop() { stop(); }

			/*********************************************************************************
			 * Restart
			 * After paused success, this will restart transport.
			 ********************************************************************************/
			virtual bool restart() { return false; }

			/*********************************************************************************
			 * Pause
			 ********************************************************************************/
			virtual bool pause() { return false; }

			/*********************************************************************************
			 * Send
			 * If notify is setted, transport will notify when the data is sent completely.
			 ********************************************************************************/
			virtual bool send(c_block_ptr b, uint32 size, bool notify = false) { return false; }

			/*********************************************************************************
			 * Send
			 * After sent, the buffer has moved ownership to transport.
			 ********************************************************************************/
			virtual bool send(flow::buffer_ptr b, bool notify = false) { return false; }

			/*********************************************************************************
			 * Send to remote address
			 * This is a synchronous operation, just for udp transport.
			 ********************************************************************************/
			virtual bool send(c_block_ptr b, uint32 size, const address &remote_address) 
			{ return false; }

			/*********************************************************************************
			 * Get local address
			 ********************************************************************************/
			virtual const address& get_local_address() const 
			{
				static address no_addr;
				return no_addr; 
			}

			/*********************************************************************************
			 * Get remote address
			 ********************************************************************************/
			virtual const address& get_remote_address() const
			{
				static address no_addr;
				return no_addr;
			}

			/*********************************************************************************
			 * Get transport type
			 ********************************************************************************/
			transport_type get_type() const { return type_; }

			/*********************************************************************************
			 * Get started status
			 ********************************************************************************/
			bool is_started() { return __is_status(TRANSPORT_STARTED); }

		protected:
			/*********************************************************************************
			 * Set channel status
			 ********************************************************************************/
			bool __set_status(uint32 o, uint32 n) 
			{ return status_.compare_exchange_strong(o, n); }

			/*********************************************************************************
			 * Check transport is in status
			 ********************************************************************************/
			bool __is_status(uint32 status) { return status_.load() == status; }

			/*********************************************************************************
			 * Set notifier
			********************************************************************************/
			void __set_notifier(void_wptr notifier) { notifier_ = notifier; }

			/*********************************************************************************
			 * Post channel event
			 ********************************************************************************/
			void __post_channel_event(poll::channel_sptr &ch, uint32 event)
			{ get_service()->post_channel_event(ch, event); }

			/*********************************************************************************
			 * Get notifier
			 ********************************************************************************/
			template <typename NotifyType>
			std::shared_ptr<NotifyType> __get_notifier()
			{ return std::move(static_pointer_cast<NotifyType>(notifier_.lock())); }

		protected:
			// Tracking tracker count
			std::atomic_int16_t tracker_cnt_;

		private:
			// Transport status
			std::atomic_uint status_;
			// Transport type
			transport_type type_;
			// Notifier
			void_wptr notifier_;
		};
		DEFINE_ALL_POINTER_TYPE(transport_base);

	}
}

#endif
