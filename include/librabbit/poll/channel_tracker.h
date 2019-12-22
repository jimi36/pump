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

#ifndef librabbit_poll_channel_tracker_h
#define librabbit_poll_channel_tracker_h

#include "librabbit/poll/channel.h"

namespace librabbit {
	namespace poll {
		
		#define TRACK_NONE  (IO_EVENT_NONE)
		#define TRACK_READ  (IO_EVNET_READ)
		#define TRACK_WRITE (IO_EVENT_WRITE)
		#define TRACK_BOTH  (IO_EVNET_READ | IO_EVENT_WRITE)

		#define TRACK_MODE_ONCE    0
		#define TRACK_MODE_KEPPING 1

		class channel_tracker
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			channel_tracker(channel_sptr &ch, int32 track_event, int32 track_mode):
				is_tracking_(false),
				track_mode_(track_mode),
				ch_(ch),
				fd_(ch->get_fd()),
				track_event_(track_event)
			{
			}
			
			/*********************************************************************************
			 * Set track status
			 ********************************************************************************/
			void track(bool on) { is_tracking_ = on; }
			
			/*********************************************************************************
			 * Get track status
			 ********************************************************************************/
			bool is_tracking() const { return is_tracking_; }
			
			/*********************************************************************************
			 * Get channel
			 ********************************************************************************/
			channel_sptr get_channel() { return ch_.lock(); }
			
			/*********************************************************************************
			 * Get fd
			 ********************************************************************************/
			int32 get_fd() const { return fd_; }
			
			/*********************************************************************************
			 * Set track event
			 ********************************************************************************/
			void set_track_event(int32 track_event) { track_event_ = track_event; }

			/*********************************************************************************
			 * Get track event
			 ********************************************************************************/
			int32 get_track_event() const { return track_event_; }

			/*********************************************************************************
			 * Get track mode
			 ********************************************************************************/
			int32 get_track_mode() const { return track_mode_; }
		
		private:
			bool is_tracking_;
			
			int32 track_mode_;

			channel_wptr ch_;
			
			int32 fd_;
			
			int32 track_event_;
		};
		DEFINE_ALL_POINTER_TYPE(channel_tracker);
	
	}
}

#endif