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
#include "pump/time/manager.h"
#include "pump/poll/afd_poller.h"
#include "pump/poll/epoll_poller.h"
#include "pump/poll/select_poller.h"

namespace pump {

service::service(bool enable_poller) : running_(false) {
    memset(pollers_, 0, sizeof(pollers_));
    if (enable_poller) {
#if defined(PUMP_HAVE_IOCP)
        pollers_[READ_POLLER_ID] = object_create<poll::afd_poller>();
        pollers_[SEND_POLLER_ID] = object_create<poll::afd_poller>();
#elif defined(PUMP_HAVE_SELECT)
        pollers_[READ_POLLER_ID] = object_create<poll::select_poller>();
        pollers_[SEND_POLLER_ID] = object_create<poll::select_poller>();
#elif defined(PUMP_HAVE_EPOLL)
        pollers_[READ_POLLER_ID] = object_create<poll::epoll_poller>();
        pollers_[SEND_POLLER_ID] = object_create<poll::epoll_poller>();
#endif
    }

    timers_ = time::manager::create();
}

service::~service() {
    if (pollers_[READ_POLLER_ID]) {
        delete pollers_[READ_POLLER_ID];
    }
    if (pollers_[SEND_POLLER_ID]) {
        delete pollers_[SEND_POLLER_ID];
    }
}

bool service::start() {
    if (running_) {
        PUMP_DEBUG_LOG("service: start failed for having started");
        return false;
    }

    running_ = true;

    if (timers_) {
        timers_->start(pump_bind(&service::__post_triggered_timers, this, _1));
    }
    if (pollers_[READ_POLLER_ID]) {
        pollers_[READ_POLLER_ID]->start();
    }
    if (pollers_[SEND_POLLER_ID]) {
        pollers_[SEND_POLLER_ID]->start();
    }

    __start_task_worker();

    __start_timer_callback_worker();

    return true;
}

void service::stop() {
    running_ = false;

    if (timers_) {
        timers_->stop();
    }
    if (pollers_[READ_POLLER_ID]) {
        pollers_[READ_POLLER_ID]->stop();
    }
    if (pollers_[SEND_POLLER_ID]) {
        pollers_[SEND_POLLER_ID]->stop();
    }
}

void service::wait_stopped() {
    if (pollers_[READ_POLLER_ID]) {
        pollers_[READ_POLLER_ID]->wait_stopped();
    }
    if (pollers_[SEND_POLLER_ID]) {
        pollers_[SEND_POLLER_ID]->wait_stopped();
    }
    if (timers_) {
        timers_->wait_stopped();
    }
    if (task_worker_) {
        task_worker_->join();
    }
    if (timer_worker_) {
        timer_worker_->join();
    }
}

void service::__post_triggered_timers(time::timer_list_sptr &tl) {
    triggered_timers_.enqueue(tl);
}

void service::__start_task_worker() {
    auto func = [&]() {
        task_callback task;
        while (running_) {
            if (posted_tasks_.dequeue(task, std::chrono::seconds(1))) {
                task();
            }
        }
    };
    task_worker_.reset(object_create<std::thread>(func), object_delete<std::thread>);
}

void service::__start_timer_callback_worker() {
    auto func = [&]() {
        time::timer_list_sptr tl;
        while (running_) {
            if (triggered_timers_.dequeue(tl, std::chrono::seconds(1))) {
                time::timer_sptr ptr;
                for (auto b = tl->begin(), e = tl->end(); b != e;) {
                    ptr = (b++)->lock();
                    if (PUMP_LIKELY(!!ptr)) {
                        ptr->handle_timeout();
                    }
                }
            }
        }
    };
    timer_worker_.reset(object_create<std::thread>(func), object_delete<std::thread>);
}

}  // namespace pump
