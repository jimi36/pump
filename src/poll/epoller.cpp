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

    epoll_poller::epoll_poller() noexcept : fd_(-1), events_(nullptr) {
#if defined(PUMP_HAVE_EPOLL)
        fd_ = ::epoll_create1(0);
        if (fd_ <= 0)
            PUMP_ERR_LOG("poll::epoll_poller: epoll_create1 failed with ec=%d",
                         net::last_errno());

        events_ = pump_malloc(sizeof(struct epoll_event) * EPOLL_EVENT_SIZE);
#endif
    }

    epoll_poller::~epoll_poller() {
#if defined(PUMP_HAVE_EPOLL)
        if (fd_ != -1)
            close(fd_);
        if (events_)
            pump_free(events_);
#endif
    }

    bool epoll_poller::__add_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        struct epoll_event ev;
        bzero(&ev, sizeof(ev));

        ev.data.ptr = tracker;

        auto listen_event = tracker->get_event();
        ev.events = EPOLLONESHOT;
        ev.events |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
        ev.events |= (listen_event & IO_EVENT_SEND) ? EL_SEND_EVENT : 0;

        if (epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), &ev) == 0 ||
            epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), &ev) == 0)
            return true;

        PUMP_WARN_LOG("poll::epoll_poller::__add_channel_tracker: ec=%d",
                      net::last_errno());
#else
        PUMP_WARN_LOG("poll::epoll_poller::__add_channel_tracker: not support");
#endif

        return false;
    }

    void epoll_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        struct epoll_event ev;
        bzero(&ev, sizeof(ev));

        ev.data.ptr = tracker;

        auto listen_event = tracker->get_event();
        ev.events = EPOLLONESHOT;
        ev.events |= (listen_event & IO_EVNET_READ) ? EL_READ_EVENT : 0;
        ev.events |= (listen_event & IO_EVENT_SEND) ? EL_SEND_EVENT : 0;

        if (epoll_ctl(fd_, EPOLL_CTL_MOD, tracker->get_fd(), &ev) != 0 ||
            epoll_ctl(fd_, EPOLL_CTL_ADD, tracker->get_fd(), &ev) != 0) {
            PUMP_WARN_LOG("poll::epoll_poller::__resume_channel_tracker: ec=%d",
                          net::last_errno());
        }
#else
        PUMP_WARN_LOG("poll::epoll_poller::__resume_channel_tracker: not support");
#endif
    }

    bool epoll_poller::__remove_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_EPOLL)
        struct epoll_event ev;
        if (epoll_ctl(fd_, EPOLL_CTL_DEL, tracker->get_fd(), &ev) == 0)
            return true;

        PUMP_WARN_LOG("poll::epoll_poller::__remove_channel_tracker: ec=%d",
                      net::last_errno());
#else
        PUMP_WARN_LOG("poll::epoll_poller::__remove_channel_tracker: not support");
#endif

        return false;
    }

    void epoll_poller::__poll(int32 timeout) {
#if defined(PUMP_HAVE_EPOLL)
        auto count =
            ::epoll_wait(fd_, (struct epoll_event *)events_, EPOLL_EVENT_SIZE, timeout);
        if (count > 0)
            __dispatch_pending_event(count);
#endif
    }

    void epoll_poller::__dispatch_pending_event(int32 count) {
#if defined(PUMP_HAVE_EPOLL)
        auto events = (struct epoll_event *)events_;

        for (int32 i = 0; i < count; ++i) {
            auto ev = events + i;

            auto tracker = (channel_tracker_ptr)ev->data.ptr;

            // If channel already not existed, channel tracker should be removed.
            PUMP_LOCK_SPOINTER(ch, tracker->get_channel());
            if (PUMP_UNLIKELY(ch == nullptr)) {
                trackers_.erase(tracker);
                continue;
            }

            tracker->set_tracked(false);

            if (ev->events & EL_READ_EVENT)
                ch->handle_io_event(IO_EVNET_READ);
            else if (ev->events & EL_SEND_EVENT)
                ch->handle_io_event(IO_EVENT_SEND);

            if (tracker->is_tracked())
                __resume_channel_tracker(tracker);
        }
#endif
    }

}  // namespace poll
}  // namespace pump
