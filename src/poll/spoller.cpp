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

#include "pump/poll/spoller.h"

namespace pump {
namespace poll {

    PUMP_INLINE static bool is_selectable(int32 fd) {
        return fd < 1024 && fd >= 0;
    }

    select_poller::select_poller() noexcept {
        tv_.tv_sec = 0;
        tv_.tv_usec = 0;
    }

    void select_poller::__poll(int32 timeout) {
        FD_ZERO(&read_fds_);
        FD_ZERO(&write_fds_);

        int32 fd = -1;
        int32 maxfd = -1;
        int32 listen_event = IO_EVENT_NONE;
        channel_tracker_ptr tracker = nullptr;
        for (auto &item : trackers_) {
            tracker = item.second.get();
            if (!tracker->is_tracked())
                continue;

            fd = tracker->get_fd();
            if (!is_selectable(fd))
                continue;

            if (maxfd < fd)
                maxfd = fd;

            listen_event = tracker->get_event();
            if (listen_event & IO_EVNET_READ)
                FD_SET(fd, &read_fds_);
            else if (listen_event & IO_EVENT_SEND)
                FD_SET(fd, &write_fds_);
        }

        tv_.tv_sec = timeout / 1000;
        tv_.tv_usec = (timeout % 1000) * 1000;
        int32 count = ::select(maxfd + 1, &read_fds_, &write_fds_, NULL, &tv_);
#if defined(WIN32)
        if (maxfd == -1 && timeout > 0)
            Sleep(1);
#endif
        if (count > 0)
            __dispatch_pending_event(&read_fds_, &write_fds_);
    }

    void select_poller::__dispatch_pending_event(const fd_set *rfds, const fd_set *wfds) {
        auto beg = trackers_.begin();
        channel_tracker_ptr tracker = nullptr;

        while (beg != trackers_.end()) {
            tracker = beg->second.get();

            // If channel already not existed, channel tracker should be removed.
            PUMP_LOCK_SPOINTER(ch, tracker->get_channel());
            if (PUMP_UNLIKELY(ch == nullptr)) {
                trackers_.erase(beg++);
                continue;
            }

#if !defined(PUMP_HAVE_IOCP) && !defined(PUMP_HAVE_EPOLL)
            int32 fd = tracker->get_fd();
            int32 listen_event = tracker->get_event();
            if (listen_event & IO_EVNET_READ) {
                if (FD_ISSET(fd, rfds)) {
                    tracker->set_tracked(false);
                    ch->handle_io_event(IO_EVNET_READ);
                }
            } else {
                if (FD_ISSET(fd, wfds)) {
                    tracker->set_tracked(false);
                    ch->handle_io_event(IO_EVENT_SEND);
                }
            }
#endif
            beg++;
        }
    }

}  // namespace poll
}  // namespace pump
