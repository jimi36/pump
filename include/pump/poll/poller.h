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

#ifndef pump_poll_poller_h
#define pump_poll_poller_h

#include "pump/net/socket.h"
#include "pump/poll/channel_tracker.h"

namespace pump {
	namespace poll {

		class LIB_EXPORT poller
		{
		protected:
			struct channel_event
			{
				channel_event(std::shared_ptr<channel> &c, uint32 e)
				{
					ch    = c;
					event = e;
				}

				channel_wptr ch;
				uint32 event;
			};
			DEFINE_ALL_POINTER_TYPE(channel_event);

			struct channel_tracker_modifier
			{
				channel_tracker_modifier(channel_tracker_sptr &t, bool o)
				{
					tracker = t;
					on = o;
				}
				channel_tracker_sptr tracker;
				bool on;
			};

		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			poller(bool pop_pending = false);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~poller();

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start();

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Wait stopping
			 ********************************************************************************/
			virtual void wait_stop();

			/*********************************************************************************
			 * Add channel tracker
			 ********************************************************************************/
			virtual bool add_channel_tracker(channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Remove channel tracker
			 ********************************************************************************/
			virtual void remove_channel_tracker(channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Awake channel tracker
			 ********************************************************************************/
			virtual void awake_channel_tracker(channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Push channel event
			 ********************************************************************************/
			virtual void push_channel_event(channel_sptr &c, uint32 event);

		protected:
			/*********************************************************************************
			 * Add channel tracker for derived class
			 ********************************************************************************/
			virtual bool __add_channel_tracker(channel_tracker_ptr tracker) { return true; }

			/*********************************************************************************
			 * Remove append channel for derived class
			 ********************************************************************************/
			virtual void __remove_channel_tracker(channel_tracker_ptr tracker) {}

			/*********************************************************************************
			 * Awake channel tracker for derived class
			 ********************************************************************************/
			virtual void __awake_channel_tracker(channel_tracker_ptr tracker) {}

			/*********************************************************************************
			 * Poll
			 * Timeout is polling timeout time. If set to -1, then no wait
			 ********************************************************************************/
			virtual void __poll(int32 timeout) {}

		private:
			/*********************************************************************************
			 * Handle channel events
			 ********************************************************************************/
			void __handle_channel_events();

			/*********************************************************************************
			 * Update channel trackers
			 ********************************************************************************/
			void __update_channel_trackers();

		protected:
			// Started status
			std::atomic_bool started_;
			// Pop pending channel status
			bool pop_pending_channel_;
			// Worker thread
			std::shared_ptr<std::thread> worker_;
			// Channel events
			std::mutex ch_event_mx_;
			volatile int32 ch_event_cnt_;
			std::list<channel_event_ptr> ch_events_;
			// Modifying channel trackers
			std::mutex tracker_mx_;
			std::vector<channel_tracker_modifier> tracker_modifiers_;
			// Channel trackers
			std::unordered_map<channel_tracker_ptr, channel_tracker_sptr> trackers_;
		};

		DEFINE_ALL_POINTER_TYPE(poller);

	}
}

#endif 
