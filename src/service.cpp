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
#include "pump/time/timer_queue.h"
#include "pump/poll/epoll_poller.h"
#include "pump/poll/select_poller.h"
#include "pump/poll/afd_poller.h"

namespace pump {

    service::service(bool enable_poller)
      : running_(false) {
        memset(pollers_, 0, sizeof(pollers_));
        if (enable_poller) {
#if defined(PUMP_HAVE_IOCP)
            pollers_[READ_POLLER] = object_create<poll::afd_poller>();
            pollers_[SEND_POLLER] = object_create<poll::afd_poller>();
#elif defined(PUMP_HAVE_SELECT)
            pollers_[READ_POLLER] = object_create<poll::select_poller>();
            pollers_[SEND_POLLER] = object_create<poll::select_poller>();
#elif defined(PUMP_HAVE_EPOLL)
            pollers_[READ_POLLER] = object_create<poll::epoll_poller>();
            pollers_[SEND_POLLER] = object_create<poll::epoll_poller>();
#endif
        }

        timers_ = time::timer_queue::create();
    }

    service::~service() {
        if (pollers_[READ_POLLER]) {
            delete pollers_[READ_POLLER];
        }
        if (pollers_[SEND_POLLER]) {
            delete pollers_[SEND_POLLER];
        }
    }

    bool service::start() {
        if (running_) {
            PUMP_WARN_LOG("service: start failed for having started");
            return false;
        }

        running_ = true;

        if (timers_) {
            timers_->start(pump_bind(&service::__post_pending_timer, this, _1));
        }
        if (pollers_[READ_POLLER]) {
            pollers_[READ_POLLER]->start();
        }
        if (pollers_[SEND_POLLER]) {
            pollers_[SEND_POLLER]->start();
        }

        __start_posted_task_worker();

        __start_timeout_timer_worker();

        return true;
    }

    void service::stop() {
        running_ = false;

        if (timers_) {
            timers_->stop();
        }
        if (pollers_[READ_POLLER]) {
            pollers_[READ_POLLER]->stop();
        }
        if (pollers_[SEND_POLLER]) {
            pollers_[SEND_POLLER]->stop();
        }
    }

    void service::wait_stopped() {
        if (pollers_[READ_POLLER]) {
            pollers_[READ_POLLER]->wait_stopped();
        }
        if (pollers_[SEND_POLLER]) {
            pollers_[SEND_POLLER]->wait_stopped();
        }
        if (timers_) {
            timers_->wait_stopped();
        }
        if (posted_task_worker_) {
            posted_task_worker_->join();
        }
        if (pending_timer_worker_) {
            pending_timer_worker_->join();
        }
    }

    bool service::add_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pi) {
        PUMP_ASSERT(pi <= SEND_POLLER);
        if (pollers_[pi]) {
            return pollers_[pi]->add_channel_tracker(tracker);
        }
        return false;
    }

    void service::remove_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pi) {
        PUMP_ASSERT(pi <= SEND_POLLER);
        if (pollers_[pi]) {
            return pollers_[pi]->remove_channel_tracker(tracker);
        }
    }

    bool service::resume_channel_tracker(poll::channel_tracker_ptr tracker, int32_t pi) {
        PUMP_ASSERT(pi <= SEND_POLLER);
        if (pollers_[pi]) {
            return pollers_[pi]->resume_channel_tracker(tracker);
        }
        return false;
    }

    bool service::post_channel_event(poll::channel_sptr &ch, int32_t event) {
        if (PUMP_LIKELY(!!pollers_[SEND_POLLER])) {
            return pollers_[SEND_POLLER]->push_channel_event(ch, event);
        }
        return false;
    }

    bool service::start_timer(time::timer_sptr &timer) {
        auto queue = timers_;
        if (PUMP_LIKELY(!!queue)) {
            return queue->start_timer(timer);
        }

        PUMP_WARN_LOG("service: start timer failed with invalid timer queue");

        return false;
    }

    void service::__start_posted_task_worker() {
        auto func = [&]() {
            posted_task_type task;
            while (running_) {
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
            time::timer_wptr wptr;
            while (running_) {
                if (pending_timers_.dequeue(wptr, std::chrono::seconds(1))) {
                    auto ptr = wptr.lock();
                    if (PUMP_LIKELY(!!ptr)) {
                        ptr->handle_timeout();
                    }
                }
            }
        };
        pending_timer_worker_.reset(object_create<std::thread>(func),
                                    object_delete<std::thread>);
    }

}  // namespace pump
