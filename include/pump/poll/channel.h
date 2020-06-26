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

#ifndef pump_poll_channel_h
#define pump_poll_channel_h

#include "pump/deps.h"
#include "pump/net/iocp.h"
#include "pump/utils/features.h"

namespace pump {
	namespace poll {

		/*********************************************************************************
		 * IO event
		 ********************************************************************************/
		#define	IO_EVENT_NONE  0x00  // none event
		#define	IO_EVNET_READ  0x01  // read event
		#define	IO_EVENT_SEND  0x02  // send event
		#define	IO_EVENT_ERROR 0x04  // error event

		/*********************************************************************************
		 * Channel opt type
		 ********************************************************************************/
		enum channel_opt_type
		{
			CH_OPT_NONE   = 0x00,
			CH_OPT_APPEND = 0x01,
			CH_OPT_UPDATE = 0x02,
			CH_OPT_DELETE = 0x03
		};

		class LIB_PUMP channel:
			public utils::noncopyable
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			explicit channel(int32 fd) PUMP_NOEXCEPT :
				ctx_(nullptr),
				fd_(fd) 
			{}

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~channel() = default;

			/*********************************************************************************
			 * Get channel fd
			 ********************************************************************************/
			PUMP_INLINE int32 get_fd() PUMP_CONST
			{ return fd_; }

			/*********************************************************************************
			 * Get channel context
			 ********************************************************************************/
			PUMP_INLINE void_ptr get_context() PUMP_CONST
			{ return ctx_; }

			/*********************************************************************************
			 * Set context
			 ********************************************************************************/
			PUMP_INLINE void set_context(void_ptr ctx)
			{ ctx_ = ctx; }

			/*********************************************************************************
			 * Handle io event
			 ********************************************************************************/
			PUMP_INLINE void handle_io_event(uint32 ev, net::iocp_task_ptr itask)
			{
				if (ev & IO_EVNET_READ)
					on_read_event(itask);
				else if (ev & IO_EVENT_SEND)
					on_send_event(itask);
			}

			/*********************************************************************************
			 * Handle channel event
			 ********************************************************************************/
			PUMP_INLINE void handle_channel_event(int32 ev) 
			{ on_channel_event(ev); }

			/*********************************************************************************
			 * Handle tracker event
			 ********************************************************************************/
			PUMP_INLINE void handle_tracker_event(int32 ev) 
			{ on_tracker_event(ev); }

		protected:
			/*********************************************************************************
			 * Set channel fd
			 ********************************************************************************/
			PUMP_INLINE void __set_fd(int32 fd)
			{ fd_ = fd; }

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) {}

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(net::iocp_task_ptr itask) {}

			/*********************************************************************************
			 * Error event callback
			 ********************************************************************************/
			virtual void on_error_event() {}

			/*********************************************************************************
			 * Channel event callback
			 ********************************************************************************/
			virtual void on_channel_event(uint32 ev) {}

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(int32 ev) {}

		protected:
			// Channel context
			void_ptr ctx_;
			// Channel fd
			int32 fd_;
		};
		DEFINE_ALL_POINTER_TYPE(channel);

	}
}

#endif
