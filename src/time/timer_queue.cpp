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
        while (!free_contexts_.empty()) {
            auto ctx = free_contexts_.front();
            object_delete(ctx);
            timers_.pop();
        }
        while (!timers_.empty()) {
            auto ctx = timers_.top();
            object_delete(ctx);
            timers_.pop();
        }
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

        switch (repeated) {
            case false:
                if (PUMP_UNLIKELY(!ptr->__start(this))) {
                    return false;
                }
                break;
            case true:
                if (PUMP_UNLIKELY(!ptr->__restart())) {
                    return false;
                }
                break;
        }

        PUMP_DEBUG_CHECK(new_timers_.enqueue(ptr));

        return true;
    }

    void timer_queue::__observe_thread() {
        // Timer context
        timer_context *ctx = nullptr;

        // Init next observe time.
        next_observe_time_ = get_clock_milliseconds() + TIMER_DEFAULT_INTERVAL;

        while (1) {
            // Get now milliseconds
            uint64_t now = get_clock_milliseconds();

            // Temp timer ptr
            timer_sptr ptr;

            // Wait unitl next observe time arrived or new timer added.
            if (next_observe_time_ > now) {
                if (new_timers_.dequeue(ptr, (next_observe_time_ - now) * 1000)) {
                    ctx = __create_timer_context(ptr);

                    timers_.push(ctx);

                    if (next_observe_time_ > ctx->overtime) {
                        next_observe_time_ = ctx->overtime;
                    }
                }
            }

            // Add new timers.
            while (new_timers_.try_dequeue(ptr)) {
                ctx = __create_timer_context(ptr);

                timers_.push(ctx);

                if (next_observe_time_ > ctx->overtime) {
                    next_observe_time_ = ctx->overtime;
                }
            }

            __observe();
        }
    }

    void timer_queue::__observe() {
        timer_context* ctx = nullptr;
        auto now = get_clock_milliseconds();
        next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;

        while (!timers_.empty()) {
            ctx = timers_.top();

            if (ctx->overtime > now) {
                next_observe_time_ = ctx->overtime;
                break;
            }

            cb_(ctx->ptr);

            timers_.pop();

            free_contexts_.push(ctx);
        }
    }

}  // namespace time
}  // namespace pump
