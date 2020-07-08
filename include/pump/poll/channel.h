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

#include "pump/toolkit/features.h"

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
			public toolkit::noncopyable
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			explicit channel(int32 fd) noexcept :
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
			PUMP_INLINE int32 get_fd() const
			{ return fd_; }

			/*********************************************************************************
			 * Get channel context
			 ********************************************************************************/
			PUMP_INLINE void_ptr get_context() const
			{ return ctx_; }

			/*********************************************************************************
			 * Set context
			 ********************************************************************************/
			PUMP_INLINE void set_context(void_ptr ctx)
			{ ctx_ = ctx; }

			/*********************************************************************************
			 * Handle io event
			 ********************************************************************************/
			PUMP_INLINE void handle_io_event(uint32 ev, void_ptr iocp_task)
			{
				if (ev & IO_EVNET_READ)
					on_read_event(iocp_task);
				else if (ev & IO_EVENT_SEND)
					on_send_event(iocp_task);
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
			virtual void on_read_event(void_ptr iocp_task) {}

			/*********************************************************************************
			 * Send event callback
			 ********************************************************************************/
			virtual void on_send_event(void_ptr iocp_task) {}

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
		
		
		
		
		#define TRACK_NONE  (IO_EVENT_NONE)
		#define TRACK_READ  (IO_EVNET_READ)
		#define TRACK_WRITE (IO_EVENT_SEND)
		#define TRACK_BOTH  (IO_EVNET_READ | IO_EVENT_SEND)

		#define TRACK_MODE_ONCE 0
		#define TRACK_MODE_LOOP 1

		#define TRACKER_EVENT_DEL 0
		#define TRACKER_EVENT_ADD 1

		class channel_tracker : 
			public toolkit::noncopyable
		{
		protected:
			friend class poller;
			friend class iocp_poller;
			friend class epoll_poller;
			friend class select_poller;

		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			channel_tracker(channel_sptr &ch, int32 ev, int32 mode) noexcept :
				is_tracked_(false),
				mode_(mode),
				event_(ev),
				fd_(ch->get_fd()),
				ch_(ch)
			{}
			
			/*********************************************************************************
			 * Get tracked status
			 ********************************************************************************/
			PUMP_INLINE bool is_tracked() const
			{ return is_tracked_; }
			
			/*********************************************************************************
			 * Set channel
			 ********************************************************************************/
			PUMP_INLINE void set_channel(channel_sptr &ch)
			{ ch_ = ch; fd_ = ch->get_fd(); }

			/*********************************************************************************
			 * Get channel
			 ********************************************************************************/
			PUMP_INLINE channel_sptr get_channel()
			{ return std::move(ch_.lock()); }
			
			/*********************************************************************************
			 * Get fd
			 ********************************************************************************/
			PUMP_INLINE int32 get_fd() const
			{ return fd_; }
			
			/*********************************************************************************
			 * Set track event
			 ********************************************************************************/
			PUMP_INLINE void set_event(int32 ev)
			{ event_ = ev; }

			/*********************************************************************************
			 * Get track event
			 ********************************************************************************/
			PUMP_INLINE int32 get_event() const
			{ return event_; }

			/*********************************************************************************
			 * Get track mode
			 ********************************************************************************/
			PUMP_INLINE int32 get_mode() const
			{ return mode_; }

		private:
			/*********************************************************************************
			 * Set tracked status
			 ********************************************************************************/
			PUMP_INLINE void __set_tracked(bool tracked)
			{ is_tracked_ = tracked; }
			
		private:
			// Status
			bool is_tracked_;
			// Track mode
			int32 mode_;
			// Track event
			int32 event_;
			// Track fd
			int32 fd_;
			// Channel
			channel_wptr ch_;
		};
		DEFINE_ALL_POINTER_TYPE(channel_tracker);

	}
}

#endif
