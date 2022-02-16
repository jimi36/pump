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

#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/time/manager.h"
#include "pump/time/timestamp.h"

namespace pump {
namespace time {

const static uint64_t TIMER_DEFAULT_INTERVAL = 100;

manager::manager() noexcept : started_(false) {}

manager::~manager() {}

bool manager::start(const timer_pending_callback &cb) {
    if (!started_.load()) {
        started_.store(true);

        if (!cb) {
            PUMP_WARN_LOG("timer pending callback invalid");
            return false;
        }
        pending_cb_ = cb;

        observer_.reset(object_create<std::thread>(
                            pump_bind(&manager::__observe_thread, this)),
                        object_delete<std::thread>);
        if (!observer_) {
            PUMP_WARN_LOG("create observer thread failed");
            started_.store(false);
            return false;
        }
    }

    return started_.load();
}

void manager::wait_stopped() {
    if (observer_) {
        observer_->join();
    }
}

bool manager::start_timer(timer_sptr &ptr) {
    if (pump_unlikely(!started_.load())) {
        PUMP_WARN_LOG("manager is not started, can't start timer");
        return false;
    }
    if (pump_unlikely(!ptr->__start(this))) {
        PUMP_WARN_LOG("start timer failed");
        return false;
    }
    if (!new_timers_.enqueue(ptr)) {
        PUMP_ERR_LOG("push timer to queue failed");
        PUMP_ABORT();
    }
    return true;
}

bool manager::restart_timer(timer_sptr &&ptr) {
    if (pump_unlikely(!started_.load())) {
        PUMP_WARN_LOG("manager is not started, can't restart timer");
        return false;
    }
    if (!new_timers_.enqueue(std::move(ptr))) {
        PUMP_ERR_LOG("push timer to queue failed");
        PUMP_ABORT();
    }
    return true;
}

void manager::__observe_thread() {
    // New timer
    timer_sptr new_timer;

    // Triggered timers
    timer_list_sptr triggered_timers;

    // Check time points
    uint64_t now_time = 0;
    uint64_t next_observe_time = 0;

    while (started_.load()) {
        if (!triggered_timers) {
            triggered_timers.reset(object_create<time::timer_list>(),
                                   object_delete<time::timer_list>);
        }

        // Update check time point.
        now_time = get_clock_milliseconds();
        next_observe_time = now_time + TIMER_DEFAULT_INTERVAL;

        // Observe triggered timers.
        __observe(triggered_timers, next_observe_time, now_time);

        // Wait until next observe time arrived.
        if (triggered_timers->empty() && next_observe_time > now_time) {
            // Add new timer.
            // Reduce dequeue timeout by 1 milliseconds for time consuming.
            if (new_timers_.dequeue(new_timer,
                                    (next_observe_time - now_time - 1) *
                                        1000)) {
                now_time = get_clock_milliseconds();

                // Queue the new timer.
                __queue_timer(triggered_timers, std::move(new_timer), now_time);

                // Try to queue more new timers.
                while (new_timers_.try_dequeue(new_timer)) {
                    __queue_timer(triggered_timers,
                                  std::move(new_timer),
                                  now_time);
                }
            }
        } else {
            // Try to queue more new timers.
            while (new_timers_.try_dequeue(new_timer)) {
                __queue_timer(triggered_timers, std::move(new_timer), now_time);
            }
        }

        if (new_timer) {
            new_timer.reset();
        }

        if (!triggered_timers->empty()) {
            pending_cb_(triggered_timers);
            triggered_timers.reset();
        }
    }
}

void manager::__observe(timer_list_sptr &tl,
                        uint64_t &next_observe_time,
                        uint64_t now) {
    if (!timers_.empty()) {
        auto end = timers_.end();
        auto beg = timers_.begin();
        auto pos = timers_.begin();

        while (pos != end && pos->first <= now) {
            tl->splice(tl->end(), std::move((pos++)->second));
        }

        // Update next observe time.
        if (pos != end) {
            next_observe_time = pos->first;
        }

        // Delete timeout timers.
        if (pos != beg) {
            timers_.erase(beg, pos);
        }
    }
}

}  // namespace time
}  // namespace pump
