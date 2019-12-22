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

#ifndef librabbit_poll_channel_h
#define librabbit_poll_channel_h

#include "librabbit/deps.h"
#include "librabbit/net/iocp.h"

namespace librabbit {
	namespace poll {

		/*********************************************************************************
		 * IO event
		 ********************************************************************************/
		#define	IO_EVENT_NONE  0x00 // none event
		#define	IO_EVNET_READ  0x01 // read event
		#define	IO_EVENT_WRITE 0x02 // write event
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

		class LIB_EXPORT channel
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			channel(int32 fd = -1);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~channel();

			/*********************************************************************************
			 * Get channel fd
			 ********************************************************************************/
			int32 get_fd() const { return fd_; }

			/*********************************************************************************
			 * Get channel context
			 ********************************************************************************/
			void_ptr get_context() const { return ctx_; }

			/*********************************************************************************
			 * Set context
			 ********************************************************************************/
			void set_context(void_ptr ctx) { ctx_ = ctx; }

			/*********************************************************************************
			 * Handle io event
			 ********************************************************************************/
			void handle_io_event(uint32 event, net::iocp_task_ptr itask);

			/*********************************************************************************
			 * Handle tracker event
			 ********************************************************************************/
			void handle_tracker_event(uint32 on);

		public:
			/*********************************************************************************
			 * Channel event callback
			 ********************************************************************************/
			virtual void on_channel_event(uint32 event) {}

		protected:
			/*********************************************************************************
			 * Set channel fd
			 ********************************************************************************/
			void __set_fd(int32 fd) { fd_ = fd; }

		protected:
			/*********************************************************************************
			 * Read event callback
			 ********************************************************************************/
			virtual void on_read_event(net::iocp_task_ptr itask) {}

			/*********************************************************************************
			 * Write event callback
			 ********************************************************************************/
			virtual void on_write_event(net::iocp_task_ptr itask) {}

			/*********************************************************************************
			 * Error event callback
			 ********************************************************************************/
			virtual void on_error_event() {}

			/*********************************************************************************
			 * Tracker event callback
			 ********************************************************************************/
			virtual void on_tracker_event(bool on) {}

		protected:
			// channel context
			void_ptr ctx_;

			// channel fd
			int32 fd_;
		};
		DEFINE_ALL_POINTER_TYPE(channel);

	}
}

#endif
