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

#include "pump/time/timer_queue.h"

namespace pump {
namespace time {

    const static uint64_t TIMER_DEFAULT_INTERVAL = 100;

    timer_queue::timer_queue() noexcept
      : started_(false), 
        next_observe_time_(0) {
    }

    timer_queue::~timer_queue() {
    }

    bool timer_queue::start(const timer_pending_callback &cb) {
        if (!started_.load()) {
            started_.store(true);

            PUMP_DEBUG_COND_FAIL(
                !cb,
                return false);
            pending_cb_ = cb;

            observer_.reset(
                object_create<std::thread>(pump_bind(&timer_queue::__observe_thread, this)),
                object_delete<std::thread>);
        }

        return started_.load();
    }

    void timer_queue::wait_stopped() {
        if (observer_) {
            observer_->join();
        }
    }

    bool timer_queue::start_timer(timer_sptr &ptr) {
        if (!started_.load()) {
            return false;
        }
        if (!ptr->__start(this)) {
            return false;
        }
        
        PUMP_DEBUG_CHECK(new_timers_.enqueue(ptr));

        return true;
    }

    bool timer_queue::restart_timer(timer_sptr &&ptr) {
        if (started_.load()) {
            PUMP_DEBUG_CHECK(new_timers_.enqueue(std::move(ptr)));
            return true;
        }
        return false;
    }

    void timer_queue::__observe_thread() {
        // New timer
        timer_sptr new_timer;
        // New timer overtime
        uint64_t new_timer_overtime;

        // Init next observe time.
        uint64_t now = get_clock_milliseconds();
        next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;

        while (1) {
            // Wait unitl next observe time arrived or new timer added.
            now = get_clock_milliseconds();
            if (next_observe_time_ > now) {
                if (new_timers_.dequeue(new_timer, (next_observe_time_ - now) * 1000)) {
                    new_timer_overtime = new_timer->time();
                    timers_.insert(std::make_pair(new_timer_overtime, std::move(new_timer)));
                } else {
                    now = next_observe_time_;
                }
                
            }

            // Try to add new timers.
            while (new_timers_.try_dequeue(new_timer)) {
                new_timer_overtime = new_timer->time();
                timers_.insert(std::make_pair(new_timer_overtime, std::move(new_timer)));
            }

            if (!timers_.empty()) {
                __observe(now);
            }

            if (timers_.empty()) {
                next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;
            } else {
                next_observe_time_ = timers_.begin()->first;
            }
        }
    }

    void timer_queue::__observe(uint64_t now) {
        // If first timer not pending just return.
        auto beg = timers_.begin();
        if (beg->first > now) {
            return;
        }

        // Callback pending timers.  
        auto pending_end = timers_.upper_bound(now);
        for (auto it = beg; it != pending_end; ++it) {
            pending_cb_(std::move(it->second));
        }

        // Remove pending timers.
        if (beg != pending_end) {
            timers_.erase(beg, pending_end);
        }
    }

}  // namespace time
}  // namespace pump
