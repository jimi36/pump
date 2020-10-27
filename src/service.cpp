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

#include "pump/service.h"
#include "pump/poll/epoller.h"
#include "pump/poll/ipoller.h"
#include "pump/poll/spoller.h"
#include "pump/time/timer_queue.h"

namespace pump {

service::service(bool has_poller)
    : running_(false),
      read_poller_(nullptr),
      send_poller_(nullptr),
      iocp_poller_(nullptr) {
    if (has_poller) {
#if defined(PUMP_HAVE_IOCP)
        iocp_poller_ = object_create<poll::iocp_poller>();
#elif defined(PUMP_HAVE_SELECT)
        read_poller_ = object_create<poll::select_poller>();
        send_poller_ = object_create<poll::select_poller>();
#elif defined(PUMP_HAVE_EPOLL)
        read_poller_ = object_create<poll::epoll_poller>();
        send_poller_ = object_create<poll::epoll_poller>();
#endif
    }

    tqueue_ = time::timer_queue::create();
}

service::~service() {
    if (read_poller_) {
        delete read_poller_;
    }
    if (send_poller_) {
        delete send_poller_;
    }
    if (iocp_poller_) {
        delete iocp_poller_;
    }
}

bool service::start() {
    if (running_) {
        PUMP_ERR_LOG("pump::service::start: had started");
        return false;
    }

    running_ = true;

    if (tqueue_) {
        tqueue_->start(pump_bind(&service::__post_timeout_timer, this, _1));
    }
    if (iocp_poller_) {
        iocp_poller_->start();
    }
    if (read_poller_) {
        read_poller_->start();
    }
    if (send_poller_) {
        send_poller_->start();
    }

    __start_posted_task_worker();

    __start_timeout_timer_worker();

    return true;
}

void service::stop() {
    running_ = false;

    if (tqueue_) {
        tqueue_->stop();
    }
    if (iocp_poller_) {
        iocp_poller_->stop();
    }
    if (read_poller_) {
        read_poller_->stop();
    }
    if (send_poller_) {
        send_poller_->stop();
    }
}

void service::wait_stopped() {
    if (iocp_poller_) {
        iocp_poller_->wait_stopped();
    }
    if (read_poller_) {
        read_poller_->wait_stopped();
    }
    if (send_poller_) {
        send_poller_->wait_stopped();
    }
    if (tqueue_) {
        tqueue_->wait_stopped();
    }
    if (posted_task_worker_) {
        posted_task_worker_->join();
    }
    if (timeout_timer_worker_) {
        timeout_timer_worker_->join();
    }
}

#if !defined(PUMP_HAVE_IOCP)
bool service::add_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pt) {
    if (pt == READ_POLLER) {
        return read_poller_->add_channel_tracker(tracker);
    } else {
        return send_poller_->add_channel_tracker(tracker);
    }
}

bool service::remove_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pt) {
    if (pt == READ_POLLER) {
        read_poller_->remove_channel_tracker(tracker);
    } else {
        send_poller_->remove_channel_tracker(tracker);
    }
    return true;
}

bool service::resume_channel_tracker(poll::channel_tracker_ptr tracker, int32_t pt) {
    if (pt == READ_POLLER) {
        read_poller_->resume_channel_tracker(tracker);
    } else {
        send_poller_->resume_channel_tracker(tracker);
    }
    return true;
}
#endif

bool service::post_channel_event(poll::channel_sptr &ch, uint32 event) {
#if defined(PUMP_HAVE_IOCP)
    iocp_poller_->push_channel_event(ch, event);
#else
    send_poller_->push_channel_event(ch, event);
#endif
    return true;
}

bool service::start_timer(time::timer_sptr &tr) {
    PUMP_LOCK_SPOINTER(queue, tqueue_);
    if (PUMP_LIKELY(!!queue)) {
        return queue->add_timer(tr);
    }

    PUMP_ERR_LOG("pump::service::start_timer: timer queue invalid");

    return false;
}

void service::__start_posted_task_worker() {
    auto func = [&]() {
        while (running_) {
            post_task_type task;
            if (posted_tasks_.dequeue(task, std::chrono::seconds(1))) {
                task();
            }
        }
    };
    posted_task_worker_.reset(object_create<std::thread>(func),
                              object_delete<std::thread>);
}

void service::__start_timeout_timer_worker() {
    auto func = [&]() {
        while (running_) {
            time::timer_wptr wptr;
            if (timeout_timers_.dequeue(wptr, std::chrono::seconds(1))) {
                PUMP_LOCK_WPOINTER(timer, wptr);
                if (timer) {
                    timer->handle_timeout();
                }
            }
        }
    };
    timeout_timer_worker_.reset(object_create<std::thread>(func),
                                object_delete<std::thread>);
}

}  // namespace pump
