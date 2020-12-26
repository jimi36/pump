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

    bool timer_queue::start(const timeout_callback &cb) {
        if (!started_.load()) {
            started_.store(true);

            PUMP_DEBUG_ASSIGN(cb, cb_, cb);

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

    bool timer_queue::add_timer(timer_sptr &&ptr, bool repeated) {
        if (!started_.load()) {
            return false;
        }

        if (!repeated && !ptr->__start(this)) {
            return false;
        }

        PUMP_DEBUG_CHECK(new_timers_.enqueue(ptr));

        return true;
    }

    void timer_queue::__observe_thread() {
        // Init next observe time.
        next_observe_time_ = get_clock_milliseconds() + TIMER_DEFAULT_INTERVAL;

        while (1) {
            // New timer
            timer_sptr new_timer;
            // Get now milliseconds
            uint64_t now = get_clock_milliseconds();

            // Wait unitl next observe time arrived or new timer added.
            if (next_observe_time_ > now) {
                if (new_timers_.dequeue(new_timer, (next_observe_time_ - now) * 1000)) {
                    timers_.insert(std::make_pair(new_timer->time(), new_timer));
                }
            }

            // Try to add new timers.
            while (new_timers_.try_dequeue(new_timer)) {
                timers_.insert(std::make_pair(new_timer->time(), new_timer));
            }

            __observe();
        }
    }

    void timer_queue::__observe() {
        // Get current time.
        uint64_t now = get_clock_milliseconds();

        auto beg = timers_.begin();
        auto end = timers_.end();
        if (beg == end) {
            next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;
            return;
        } else if (beg->first > now) {
            next_observe_time_ = beg->first;
            return;
        }

        // Callback pending timers.  
        auto pending_end = timers_.upper_bound(now);
        for (auto it = beg; it != pending_end; ++it) {
            cb_(it->second);
        }

        // Update next observe time.
        if (pending_end != end) {
            next_observe_time_ = pending_end->first;
        } else {
            next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;
        }

        // Remove pending timers.
        if (beg != pending_end) {
            timers_.erase(beg, pending_end);
        }
    }

}  // namespace time
}  // namespace pump
