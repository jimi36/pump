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

    PUMP_INLINE static bool is_selectable(pump_socket fd) {
        return fd < 1024 && fd >= 0;
    }

    select_poller::select_poller() noexcept {
#if defined(PUMP_HAVE_SELECT)
        FD_ZERO(&read_fds_);
        FD_ZERO(&write_fds_);
        tv_.tv_sec = 0;
        tv_.tv_usec = 0;
#endif
    }

    bool select_poller::__install_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_SELECT)
        return true;
#else
        return false;
#endif
    }

    bool select_poller::__uninstall_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_SELECT)
        return true;
#else
        return false;
#endif
    }

    bool select_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_SELECT)
        return true;
#else
        return false;
#endif
    }

    void select_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_SELECT)
        FD_ZERO(&read_fds_);
        FD_ZERO(&write_fds_);

        pump_socket fd = -1;
        pump_socket maxfd = -1;
        int32_t listen_event = IO_EVENT_NONE;
        channel_tracker_ptr tracker = nullptr;
        for (auto &item : trackers_) {
            tracker = item.second.get();
            if (!tracker->is_tracked()) {
                continue;
            }

            fd = tracker->get_fd();
            if (!is_selectable(fd)) {
                continue;
            }

            if (maxfd < fd) {
                maxfd = fd;
            }

            listen_event = tracker->get_expected_event();
            if (listen_event & IO_EVENT_READ) {
                FD_SET(fd, &read_fds_);
            } else if (listen_event & IO_EVENT_SEND) {
                FD_SET(fd, &write_fds_);
            }
        }

        tv_.tv_sec = timeout / 1000;
        tv_.tv_usec = (timeout % 1000) * 1000;
        int32_t count = ::select((int32_t)maxfd + 1, &read_fds_, &write_fds_, NULL, &tv_);
#if defined(OS_WINDOWS)
        if (maxfd == -1 && timeout > 0) {
            Sleep(1);
        }
#endif
        if (count > 0) {
            __dispatch_pending_event(&read_fds_, &write_fds_);
        }
#endif
    }

    void select_poller::__dispatch_pending_event(const fd_set *rfds, const fd_set *wfds) {
#if defined(PUMP_HAVE_SELECT)
        auto beg = trackers_.begin();
        while (beg != trackers_.end()) {
            // If channel is invalid, channel tracker should be removed.
            auto tracker = beg->second.get();
            auto ch = tracker->get_channel();
            if (PUMP_UNLIKELY(!ch)) {
                PUMP_DEBUG_LOG("select_poller: remove tracker for invalid channel");
                trackers_.erase(beg++);
                continue;
            }

            pump_socket fd = tracker->get_fd();
            if (FD_ISSET(fd, rfds)) {
                if (tracker->untrack()) {
                    ch->handle_io_event(IO_EVENT_READ);
                }
            } else if (FD_ISSET(fd, wfds)) {
                if (tracker->untrack()) {
                    ch->handle_io_event(IO_EVENT_SEND);
                }
            }

            beg++;
        }
#endif
    }

}  // namespace poll
}  // namespace pump
