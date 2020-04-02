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

#ifndef pump_poll_epoll_poller_h
#define pump_poll_epoll_poller_h

#include "pump/poll/poller.h"

#ifndef WIN32
#define EL_TRI_TYPE		(0) // (EPOLLET)
#define EL_READ_EVENT	(EPOLLIN | EPOLLPRI | EPOLLRDHUP)
#define EL_WRITE_EVENT	(EPOLLOUT)
#define EL_ERROR_EVENT	(EPOLLERR | EPOLLHUP)
#endif

namespace pump {
	namespace poll {

		class LIB_EXPORT epoll_poller: public poller
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			epoll_poller(bool pop_pending);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~epoll_poller();

		protected:
			/*********************************************************************************
			 * Add channel tracker for derived class
			 ********************************************************************************/
			virtual bool __add_channel_tracker(channel_tracker_ptr tracker);

			/*********************************************************************************
			 * Remove append channel for derived class
			 ********************************************************************************/
			virtual void __remove_channel_tracker(channel_tracker_ptr tracker);

			/*********************************************************************************
			 * Pause channel tracker for derived class
			 ********************************************************************************/
			virtual void __pause_channel_tracker(channel_tracker_ptr tracker);

			/*********************************************************************************
			 * Awake channel tracker for derived class
			 ********************************************************************************/
			virtual void __awake_channel_tracker(channel_tracker_ptr tracker);

			/*********************************************************************************
			 * Poll
			 ********************************************************************************/
			virtual void __poll(int32 timeout);

		private:
			/*********************************************************************************
			 * Dispatch pending event
			 ********************************************************************************/
			void __dispatch_pending_event(int32 count);

#ifndef WIN32
		private:
			int32 epollfd_;
			std::vector<struct epoll_event> events_;
			std::unordered_map<channel_tracker_ptr, channel_tracker_sptr> waiting_trackers_;
#endif
		};

		DEFINE_ALL_POINTER_TYPE(epoll_poller);

	}
}

#endif
