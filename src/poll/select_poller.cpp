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

#include "pump/poll/select_poller.h"

namespace pump {
	namespace poll {

		static bool is_selectable(int32 fd)
		{
			return  fd < 1024 && fd >= 0;
		}

		select_poller::select_poller(bool pop_pending) :
			poller(pop_pending)
		{
			tv_.tv_sec = 0;
			tv_.tv_usec = 0;
		}

		select_poller::~select_poller()
		{
		}

		void select_poller::__poll(int32 timeout)
		{
			FD_ZERO(&rfds_);
			FD_ZERO(&wfds_);

			int32 maxfd = -1;
			for (auto item: trackers_)
			{
				auto tracker = item.second.get();
				if (!tracker->is_tracking())
					continue;

				int32 fd = tracker->get_fd();
				if (!is_selectable(fd))
					assert(false);

				if (maxfd < fd)
					maxfd = fd;

				int32 listen_event = tracker->get_event();
				if (listen_event & IO_EVNET_READ)
					FD_SET(fd, &rfds_);
				if (listen_event & IO_EVENT_SEND)
					FD_SET(fd, &wfds_);
			}

			tv_.tv_sec = timeout / 1000;
			tv_.tv_usec = (timeout % 1000) * 1000;
			int32 count = ::select(maxfd + 1, &rfds_, &wfds_, NULL, &tv_);
#ifdef WIN32
			if (maxfd == -1)
			{
				std::unique_lock<std::mutex> lck(mx_);
				cv_.wait_for(lck, std::chrono::milliseconds(timeout));
			}
#endif
			if (count > 0)
				__dispatch_pending_event(rfds_, wfds_);
		}

		void select_poller::__dispatch_pending_event(fd_set &rfds, fd_set &wfds)
		{
			auto beg = trackers_.begin();
			while (beg != trackers_.end())
			{
				auto tracker = beg->second.get();
				auto ch_locker = tracker->get_channel();
				auto ch = ch_locker.get();

				// If the channel is already not existed, the channel tracker should be distroied at here.
				if (ch == nullptr)
				{
					trackers_.erase(beg++);
					continue;
				}

				int32 fd = tracker->get_fd();
				PUMP_ASSERT(fd == ch->get_fd());

				uint32 pending_event = IO_EVENT_NONE;
				if (FD_ISSET(fd, &rfds))
					pending_event |= IO_EVNET_READ;
				if (FD_ISSET(fd, &wfds))
					pending_event |= IO_EVENT_SEND;

				if (pending_event != IO_EVENT_NONE && tracker->is_tracking())
				{
					if (pop_pending_channel_)
						tracker->set_tracking(false);

					ch->handle_io_event(pending_event, nullptr);
				}

				beg++;
			}
		}

	}
}
