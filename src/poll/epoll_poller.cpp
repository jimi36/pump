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

#include "librabbit/poll/epoll_poller.h"

namespace librabbit {
	namespace poll {

		epoll_poller::epoll_poller(bool pop_pending): 
			poller(pop_pending)
		{
#ifndef WIN32
			events_.resize(1024);
			epollfd_ = ::epoll_create1(0);
#endif
		}

		epoll_poller::~epoll_poller()
		{
#ifndef WIN32
			if (epollfd_ != -1)
				close(epollfd_);
#endif
		}

		bool epoll_poller::__add_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			int32 listen_event = tracker->get_track_event();
			struct epoll_event ev;
			bzero(&ev, sizeof(ev));
			ev.data.ptr  = tracker;
			ev.io_event  = EL_TRI_TYPE;
			ev.io_event |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
			ev.io_event |= (listen_event & IO_EVENT_WRITE) ? EL_WRITE_EVENT : 0;
			ev.io_event |= pop_pending_channel_ ? EPOLLONESHOT : 0;
			return epoll_ctl(epollfd_, EPOLL_CTL_ADD, tracker->get_fd(), &ev) == 0;
#else
			return false;
#endif
		}

		void epoll_poller::__awake_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			tracker->track(TRACK_ON);

			int32 listen_event = tracker->get_track_event();
			struct epoll_event ev;
			bzero(&ev, sizeof(ev));
			ev.data.ptr  = tracker;
			ev.io_event  = EL_TRI_TYPE;
			ev.io_event |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
			ev.io_event |= (listen_event & IO_EVENT_WRITE) ? EL_WRITE_EVENT : 0;
			ev.io_event |= pop_pending_channel_ ? EPOLLONESHOT : 0;
			epoll_ctl(epollfd_, EPOLL_CTL_MOD, tracker->get_fd(), &ev) == 0;
#endif
		}

		void epoll_poller::__remove_channel_tracker(channel_tracker_ptr tracker)
		{
#ifndef WIN32
			struct epoll_event ev;
			epoll_ctl(epollfd_, EPOLL_CTL_DEL, tracker->get_fd(), &ev);
#endif
		}

		void epoll_poller::__poll(int32 timeout)
		{
#ifndef WIN32
			int32 count = ::epoll_wait(epollfd_, &(*events_.begin()), events_.size(), timeout);
			if (count > 0)
				__fill_active_channels(count);
#endif
		}

		void epoll_poller::__dispatch_pending_event(int32 count)
		{
#ifndef WIN32
			for (int32 i = 0; i < count; ++i)
			{
				auto tracker = (channel_tracker_ptr)events_[i].data.ptr;
				auto it = trackers_.find(tracker);
				if (it != trackers_.end())
				{
					auto ch_locker = tracker->get_channel().lock();
					auto ch = ch_locker.get();

					// If the channel is already not existed, the channel tracker should be distroied at here.
					if (ch == nullptr)
					{
						// Stop listening from epoll.
						struct epoll_event ev;
						epoll_ctl(epollfd_, EPOLL_CTL_DEL, tracker->get_fd(), &ev);

						trackers_.erase(it);
						continue;
					}

					int32 pending_event = IO_EVENT_NONE;
					if (events_[i].io_event & EL_READ_EVENT)
						pending_event |= IO_EVNET_READ;
					if (events_[i].io_event & EL_WRITE_EVENT)
						pending_event |= IO_EVENT_WRITE;

					if (pop_pending_channel_)
						tracker->track(TRACK_OFF);

					if (pending_event != IO_EVENT_NONE)
						ch->handle_io_event(pending_event, nullptr);

					if (pop_pending_channel_ && tracker->is_tracking())
						__awake_channel_tracker(tracker);
				}
			}
#endif
		}

	}
}