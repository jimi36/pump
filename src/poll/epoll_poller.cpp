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

#if defined(PUMP_HAVE_EPOLL)
#include <sys/epoll.h>
#endif

namespace pump {
namespace poll {

#if defined(PUMP_HAVE_EPOLL)
    const static uint32_t EL_TRI_TYPE = 0;  // (EPOLLET)
    const static uint32_t EL_READ_EVENT = (EPOLLONESHOT | EPOLLIN | EPOLLPRI | EPOLLRDHUP);
    const static uint32_t EL_SEND_EVENT = (EPOLLONESHOT | EPOLLOUT);
    const static uint32_t EL_ERR_EVENT = (EPOLLERR | EPOLLHUP);
#endif

    epoll_poller::epoll_poller() noexcept
      : fd_(-1), 
        events_(nullptr),
        max_event_count_(1024),
        cur_event_count_(0) {
#if defined(PUMP_HAVE_EPOLL)
        fd_ = ::epoll_create1(0);
        if (fd_ <= 0) {
            PUMP_ERR_LOG(
                "epoll_poller: epoll_create1 failed %d", net::last_errno());
        }

        events_ = pump_malloc(sizeof(struct epoll_event) * max_event_count_);
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

    bool epoll_poller::__install_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto expected_event = tracker->get_expected_event();
        auto event = tracker->get_event();
        event->data.ptr = tracker;
        if (expected_event & IO_EVENT_READ) {
            event->events = EL_READ_EVENT;
        } else if (expected_event & IO_EVENT_SEND) {
            event->events = EL_SEND_EVENT;
        }
        if (epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), event) == 0 ||
            epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), event) == 0) {
            cur_event_count_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }

        PUMP_WARN_LOG(
            "epoll_poller: add channel tracker failed %d", net::last_errno());
#else
        PUMP_ERR_LOG("epoll_poller: add channel tracker failed for not support");
#endif
        return false;
    }

    bool epoll_poller::__uninstall_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto event = tracker->get_event();
        if (epoll_ctl(fd_, EPOLL_CTL_DEL, tracker->get_fd(), event) == 0) {
            cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
            return true;           
        }

        PUMP_WARN_LOG(
                "epoll_poller: remove channel tracker failed %d", net::last_errno());
#else
        PUMP_ERR_LOG("epoll_poller: remove channel tracker failed for not support");
#endif
        return false;
    }

    bool epoll_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        auto expected_event = tracker->get_expected_event();
        auto event = tracker->get_event();
        event->data.ptr = tracker;
        if (expected_event & IO_EVENT_READ) {
            event->events = EL_READ_EVENT;
        } else if (expected_event & IO_EVENT_SEND) {
            event->events = EL_SEND_EVENT;
        }
        if (epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), event) == 0 ||
            epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), event) == 0) {
            return true;
        }

        PUMP_WARN_LOG(
            "epoll_poller: resume channel tracker failed %d", net::last_errno());
#else
        PUMP_ERR_LOG("epoll_poller: resume channel tracker failed for not support");
#endif
        return false;
    }

    void epoll_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_EPOLL)
        auto cur_event_count = cur_event_count_.load(std::memory_order_relaxed);
        if (PUMP_UNLIKELY(cur_event_count > max_event_count_)) {
            max_event_count_ = cur_event_count;
            events_ = pump_realloc(events_, sizeof(struct epoll_event) * max_event_count_);
            PUMP_ASSERT(events_);
            PUMP_DEBUG_LOG("epoll_poller: update epoll event max count %d", max_event_count_);
        }

        auto count = ::epoll_wait(fd_, 
                                  (struct epoll_event*)events_, 
                                  max_event_count_, 
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
            if (tracker->untrack()) {
                auto ch = tracker->get_channel();
                if (ch) {
                    ch->handle_io_event(tracker->get_expected_event());
                }
            }
        }
#endif
    }

}  // namespace poll
}  // namespace pump
