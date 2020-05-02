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

#include "pump/poll/epoll_poller.h"

namespace pump {
	namespace poll {

#define EPOLL_EVENT_SIZE 1024

		epoll_poller::epoll_poller(bool pop_pending): 
			poller(pop_pending)
		{
#ifndef WIN32
			epoll_fd_ = ::epoll_create1(0);
			epoll_mem_ = malloc(sizeof(struct epoll_event) * EPOLL_EVENT_SIZE);
#endif
		}

		epoll_poller::~epoll_poller()
		{
#ifndef WIN32
			if (epoll_fd_ != -1)
				close(epoll_fd_);
			if (epoll_mem_)
				free(epoll_mem_);
#endif
		}

		bool epoll_poller::__add_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			struct epoll_event ev;
			bzero(&ev, sizeof(ev));

			ev.data.ptr = tracker;

			ev.events = EL_TRI_TYPE;

			int32 listen_event = tracker->get_track_event();
			ev.events |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
			ev.events |= (listen_event & IO_EVENT_SEND) ? EL_WRITE_EVENT : 0;
			ev.events |= pop_pending_channel_ ? EPOLLONESHOT : 0;
	
			return epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, tracker->get_fd(), &ev) == 0;
#else
			return false;
#endif
		}

		void epoll_poller::__awake_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			struct epoll_event ev;
			bzero(&ev, sizeof(ev));

			ev.data.ptr = tracker;

			ev.events = EL_TRI_TYPE;

			int32 listen_event = tracker->get_track_event();
			ev.events |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
			ev.events |= (listen_event & IO_EVENT_SEND) ? EL_WRITE_EVENT : 0;
			ev.events |= pop_pending_channel_ ? EPOLLONESHOT : 0;

			//epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, tracker->get_fd(), &ev);
			epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, tracker->get_fd(), &ev);
#endif
		}

		void epoll_poller::__remove_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			struct epoll_event ev;
			epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, tracker->get_fd(), &ev);
#endif
		}

		void epoll_poller::__pause_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			struct epoll_event ev;
			epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, tracker->get_fd(), &ev);
#endif
		}

		void epoll_poller::__poll(int32 timeout)
		{
#ifndef WIN32
			int32 count = ::epoll_wait(epoll_fd_, (struct epoll_event*)epoll_mem_, EPOLL_EVENT_SIZE, timeout);
			if (count > 0)
				__dispatch_pending_event(count);
#endif
		}

		void epoll_poller::__dispatch_pending_event(int32 count)
		{
#ifndef WIN32
			auto events = (struct epoll_event*)epoll_mem_;

			for (int32 i = 0; i < count; ++i)
			{
				auto tracker = (channel_tracker_ptr)events[i].data.ptr;
				
				// Epoll will automatically deltete closed fd.
				// If channel already not existed, channel tracker should be removed.
				PUMP_LOCK_SPOINTER_EXPR(ch, tracker->get_channel(), false,
					trackers_.erase(tracker); continue);

				int32 pending_event = IO_EVENT_NONE;
				if (events[i].events & EL_READ_EVENT)
					pending_event |= IO_EVNET_READ;
				if (events[i].events & EL_WRITE_EVENT)
					pending_event |= IO_EVENT_SEND;

				if (pop_pending_channel_)
					tracker->__set_tracking(false);

				ch->handle_io_event(pending_event, nullptr);
			}
#endif
		}

	}
}
