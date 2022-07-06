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
// const static uint32_t EL_TRI_TYPE = 0;  // (EPOLLET)
const static uint32_t epoll_read = (EPOLLONESHOT | EPOLLIN | EPOLLPRI | EPOLLRDHUP);
const static uint32_t epoll_send = (EPOLLONESHOT | EPOLLOUT);
const static uint32_t epoll_error = (EPOLLERR | EPOLLHUP);
#endif

epoll_poller::epoll_poller() noexcept :
    fd_(-1),
    events_(nullptr),
    max_event_count_(1024),
    cur_event_count_(0) {
#if defined(PUMP_HAVE_EPOLL)
    if ((fd_ = ::epoll_create1(0)) < 0) {
        pump_err_log("create epoll fd failed %d", net::last_errno());
        pump_abort();
    }

    events_ = pump_malloc(sizeof(struct epoll_event) * max_event_count_);
    if (events_ == nullptr) {
        pump_err_log("allocate epoll events memory failed");
        pump_abort();
    }
#else
    pump_abort();
#endif
}

epoll_poller::~epoll_poller() {
#if defined(PUMP_HAVE_EPOLL)
    if (fd_ != -1) {
        close(fd_);
    }
    if (events_ != nullptr) {
        pump_free(events_);
    }
#endif
}

bool epoll_poller::__install_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_EPOLL)
    auto expected_event = tracker->get_expected_event();
    auto event = tracker->get_event();
    event->data.ptr = tracker;
    if (expected_event & io_read) {
        event->events = epoll_read;
    } else if (expected_event & io_send) {
        event->events = epoll_send;
    }
    if (epoll_ctl(
            fd_,
            EPOLL_CTL_ADD,
            tracker->get_fd(),
            event) == 0) {
        cur_event_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
#endif
    pump_warn_log("install channel tracker failed %d", net::last_errno());
    return false;
}

bool epoll_poller::__uninstall_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_EPOLL)
    auto event = tracker->get_event();
    if (epoll_ctl(
            fd_,
            EPOLL_CTL_DEL,
            tracker->get_fd(),
            event) == 0) {
        cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
        return true;
    } else if (errno == ENOENT) {
        return true;
    }
#endif
    pump_warn_log("uninstall channel tracker failed %d", net::last_errno());
    return false;
}

bool epoll_poller::__resume_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_EPOLL)
    auto expected_event = tracker->get_expected_event();
    auto event = tracker->get_event();
    event->data.ptr = tracker;
    if (expected_event & io_read) {
        event->events = epoll_read;
    } else if (expected_event & io_send) {
        event->events = epoll_send;
    }
    if (epoll_ctl(
            fd_,
            EPOLL_CTL_MOD,
            tracker->get_fd(),
            event) == 0) {
        return true;
    }
#endif
    pump_warn_log("resume channel tracker failed %d", net::last_errno());
    return false;
}

void epoll_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_EPOLL)
    auto cur_event_count = cur_event_count_.load(std::memory_order_relaxed);
    if (pump_unlikely(cur_event_count > max_event_count_)) {
        max_event_count_ = cur_event_count;
        events_ = pump_realloc(events_, sizeof(struct epoll_event) * max_event_count_);
        if (events_ == nullptr) {
            pump_abort_with_log("reallocate epoll events memory failed");
        }
    }

    auto count = ::epoll_wait(
        fd_,
        (struct epoll_event *)events_,
        max_event_count_,
        timeout);
    if (count > 0) {
        __dispatch_pending_event(count);
    }
#endif
}

void epoll_poller::__dispatch_pending_event(int32_t count) {
#if defined(PUMP_HAVE_EPOLL)
    auto ev_beg = (epoll_event *)events_;
    auto ev_end = (epoll_event *)events_ + count;
    for (auto ev = ev_beg; ev != ev_end; ++ev) {
        // If channel is invalid, tracker should be removed.
        auto tracker = (channel_tracker *)ev->data.ptr;
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
