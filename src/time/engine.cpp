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
#include "pump/time/engine.h"
#include "pump/time/timestamp.h"

namespace pump {
namespace time {

const static uint64_t default_observe_interval_ns = 200 * 1000000;  // 200 ms

engine::engine() noexcept
  : started_(false) {
}

bool engine::start(const timer_pending_callback &cb) {
    if (!started_.load()) {
        started_.store(true);

        if (!cb) {
            pump_debug_log("timer pending callback invalid");
            return false;
        }
        pending_cb_ = cb;

        observer_.reset(
            pump_object_create<std::thread>(
                pump_bind(&engine::__observe_thread, this)),
            pump_object_destroy<std::thread>);
        if (!observer_) {
            pump_debug_log("create observer thread failed");
            started_.store(false);
            return false;
        }
    }

    return started_.load();
}

void engine::wait_stopped() {
    if (observer_) {
        observer_->join();
    }
}

bool engine::start_timer(timer_sptr &ptr) {
    if (pump_unlikely(!started_.load())) {
        pump_debug_log("engine is not started, can't start timer");
        return false;
    }
    if (pump_unlikely(!ptr->__start(this))) {
        pump_debug_log("start timer failed");
        return false;
    }
    if (!new_timers_.enqueue(ptr)) {
        pump_abort_with_log("push timer to queue failed");
    }
    return true;
}

bool engine::restart_timer(timer_sptr &&ptr) {
    if (pump_unlikely(!started_.load())) {
        pump_debug_log("engine is not started, can't restart timer");
        return false;
    }
    if (!new_timers_.enqueue(std::move(ptr))) {
        pump_abort_with_log("push timer to queue failed");
    }
    return true;
}

void engine::__observe_thread() {
    // New timer
    timer_sptr new_timer;

    // Triggered timers
    timer_list_sptr triggered_timers;

    while (started_.load()) {
        if (!triggered_timers) {
            triggered_timers.reset(
                pump_object_create<time::timer_list>(),
                pump_object_destroy<time::timer_list>);
        }

        // Every loop max new timers count.
        int32_t max_new_timers = 1024;

        // Init check time point.
        auto now_time_ns = get_clock_nanoseconds();
        auto next_observe_time_ns = now_time_ns + default_observe_interval_ns;

        // Observe triggered timers.
        __observe(triggered_timers, next_observe_time_ns, now_time_ns);

        // Update now time.
        now_time_ns = get_clock_nanoseconds();

        // Wait until next observe time arrived.
        if (triggered_timers->empty() && next_observe_time_ns > now_time_ns) {
            // Get new timer.
            auto wait_time_us = (next_observe_time_ns - now_time_ns) / 1000;
            new_timers_.dequeue(new_timer, wait_time_us);

            // Update now time.
            now_time_ns = get_clock_nanoseconds();

            if (new_timer) {
                // Queue the new timer.
                __queue_timer(new_timer, now_time_ns);
                // Reduce max new timers count.
                max_new_timers--;
            }
        }

        // Try to queue more new timers.
        while (max_new_timers-- > 0 && new_timers_.try_dequeue(new_timer)) {
            __queue_timer(new_timer, now_time_ns);
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

void engine::__observe(
    timer_list_sptr &tl,
    uint64_t &next_time_ns,
    uint64_t now_ns) {
    if (!timers_.empty()) {
        auto end = timers_.end();
        auto beg = timers_.begin();
        auto pos = timers_.begin();

        while (pos != end && pos->first <= now_ns) {
            tl->splice(tl->end(), std::move((pos++)->second));
        }

        // Update next observe time.
        if (pos != end) {
            next_time_ns = pos->first;
        }

        // Delete timeout timers.
        if (pos != beg) {
            timers_.erase(beg, pos);
        }
    }
}

}  // namespace time
}  // namespace pump
