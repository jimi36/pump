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

#ifndef pump_poll_channel_tracker_h
#define pump_poll_channel_tracker_h

#include "pump/poll/channel.h"

namespace pump {
	namespace poll {
		
		#define TRACK_NONE  (IO_EVENT_NONE)
		#define TRACK_READ  (IO_EVNET_READ)
		#define TRACK_WRITE (IO_EVENT_SEND)
		#define TRACK_BOTH  (IO_EVNET_READ | IO_EVENT_SEND)

		#define TRACK_MODE_ONCE 0
		#define TRACK_MODE_LOOP 1

		#define TRACKER_EVENT_DEL 0
		#define TRACKER_EVENT_ADD 1

		class channel_tracker : 
			public utils::noncopyable
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
			channel_tracker(channel_sptr &ch, int32 ev, int32 mode) PUMP_NOEXCEPT :
				is_tracked_(false),
				mode_(mode),
				event_(ev),
				fd_(ch->get_fd()),
				ch_(ch)
			{}
			
			/*********************************************************************************
			 * Get tracked status
			 ********************************************************************************/
			PUMP_INLINE bool is_tracked() PUMP_CONST
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
			PUMP_INLINE int32 get_fd() PUMP_CONST
			{ return fd_; }
			
			/*********************************************************************************
			 * Set track event
			 ********************************************************************************/
			PUMP_INLINE void set_event(int32 ev)
			{ event_ = ev; }

			/*********************************************************************************
			 * Get track event
			 ********************************************************************************/
			PUMP_INLINE int32 get_event() PUMP_CONST
			{ return event_; }

			/*********************************************************************************
			 * Get track mode
			 ********************************************************************************/
			PUMP_INLINE int32 get_mode() PUMP_CONST
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