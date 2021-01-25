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

#include "pump/poll/epoller.h"

#if defined(PUMP_HAVE_EPOLL)
#include <sys/epoll.h>
#endif

namespace pump {
namespace poll {

#if defined(PUMP_HAVE_EPOLL)
#define EL_TRI_TYPE (0)  // (EPOLLET)
#define EL_READ_EVENT (EPOLLIN | EPOLLPRI | EPOLLRDHUP)
#define EL_SEND_EVENT (EPOLLOUT)
#define EL_ERROR_EVENT (EPOLLERR | EPOLLHUP)
#endif

#if defined(PUMP_HAVE_EPOLL)
#define EPOLL_EVENT_SIZE 1024
#endif

    epoll_poller::epoll_poller() noexcept
      : fd_(-1), 
        events_(nullptr) {
#if defined(PUMP_HAVE_EPOLL)
        fd_ = ::epoll_create1(0);
        if (fd_ <= 0) {
            PUMP_ERR_LOG(
                "epoll_poller: epoll_create1 failed %d", net::last_errno());
        }

        events_ = pump_malloc(sizeof(struct epoll_event) * EPOLL_EVENT_SIZE);
#endif
    }

    epoll_poller::~epoll_poller() {
#if defined(PUMP_HAVE_EPOLL)
        if (fd_ != -1) {
            close(fd_);
        }
        if (events_) {
            pump_free(events_);
        }
#endif
    }

    bool epoll_poller::__add_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto ev = tracker->get_event();
        auto epoll_ev = tracker->get_epoll_event();
        epoll_ev->data.ptr = tracker;
        if (ev & IO_EVENT_READ) {
            epoll_ev->events = EPOLLONESHOT | EL_READ_EVENT;
        } else if (ev & IO_EVENT_SEND) {
            epoll_ev->events = EPOLLONESHOT | EL_SEND_EVENT;
        }
        if (epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), epoll_ev) == 0 ||
            epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), epoll_ev) == 0) {
            return true;
        }

        PUMP_DEBUG_LOG(
            "epoll_poller: add channel tracker failed %d", net::last_errno());
#else
        PUMP_ERR_LOG("epoll_poller: add channel tracker failed for not support");
#endif
        return false;
    }

    bool epoll_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto ev = tracker->get_event();
        auto epoll_ev = tracker->get_epoll_event();
        epoll_ev->data.ptr = tracker;
        if (ev & IO_EVENT_READ) {
            epoll_ev->events = EPOLLONESHOT | EL_READ_EVENT;
        } else if (ev & IO_EVENT_SEND) {
            epoll_ev->events = EPOLLONESHOT | EL_SEND_EVENT;
        }
        if (epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), epoll_ev) == 0 ||
            epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), epoll_ev) == 0) {
            return true;
        }

        PUMP_DEBUG_LOG(
            "epoll_poller: resume channel tracker failed %d", net::last_errno());
#else
        PUMP_ERR_LOG("epoll_poller: resume channel tracker failed for not support");
#endif
        return false;
    }

    bool epoll_poller::__remove_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto epoll_ev = tracker->get_epoll_event();
        if (epoll_ctl(fd_, EPOLL_CTL_DEL, tracker->get_fd(), epoll_ev) != 0) {
            PUMP_WARN_LOG(
                "epoll_poller: remove channel tracker failed %d", net::last_errno());
            return false;
        }

        return true;
#else
        PUMP_ERR_LOG("epoll_poller: remove channel tracker failed for not support");
        return false;
#endif
    }

    void epoll_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_EPOLL)
        auto count = ::epoll_wait(fd_, 
                                  (struct epoll_event*)events_, 
                                  EPOLL_EVENT_SIZE, 
                                  timeout);
        if (count > 0) {
            __dispatch_pending_event(count);
        }
#endif
    }

    void epoll_poller::__dispatch_pending_event(int32_t count) {
#if defined(PUMP_HAVE_EPOLL)
        channel_tracker_ptr tracker;
        auto ev_beg = (epoll_event*)events_;
        auto ev_end = (epoll_event*)events_ + count;
        for (auto ev = ev_beg; ev != ev_end; ++ev) {
            // If channel is invalid, tracker should be removed.
            tracker = (channel_tracker_ptr)ev->data.ptr;
            auto ch = tracker->get_channel();
            if (PUMP_UNLIKELY(!ch)) {
                trackers_.erase(tracker);
                continue;
            }

            tracker->untrack();

            ch->handle_io_event(tracker->get_event());
        }
#endif
    }

}  // namespace poll
}  // namespace pump
