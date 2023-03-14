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

#include "pump/memory.h"
#include "pump/time/timer.h"
#include "pump/time/engine.h"
#include "pump/time/timestamp.h"

namespace pump {
namespace time {

timer::timer(
    bool repeated,
    uint64_t timeout,
    const timer_callback &cb) noexcept
  : e_(nullptr), 
    state_(timer_state_none),
    repeated_(repeated),
    timeout_ns_(timeout),
    cb_(cb) {
}

void timer::stop() noexcept {
    state_.store(timer_state_stopped);
}

void timer::handle_timeout() {
    if (__set_state(timer_state_started, timer_state_pending)) {
        cb_();

        if (pump_likely(repeated_)) {
            if (__set_state(timer_state_pending, timer_state_started)) {
                // Add to timer engine.
                e_->restart_timer(shared_from_this());
            }
        } else {
            __set_state(timer_state_pending, timer_state_stopped);
        }
    }
}

bool timer::__start(engine *e) noexcept {
    if (!__set_state(timer_state_none, timer_state_started)) {
        return false;
    }

    e_ = e;

    return true;
}

bool timer::__set_state(int32_t expected, int32_t desired) noexcept {
    return state_.compare_exchange_strong(expected, desired);
}

sync_timer::sync_timer(
    uint64_t timeout_ns,
    const timer_callback& cb)
  : cb_(cb) {
    raw_ = timer::create(
        false, 
        timeout_ns, 
        pump_bind(&sync_timer::__handle_timeout, this));
}

bool sync_timer::start(engine *e) {
    if (!raw_ || !e->start_timer(raw_)) {
        return false;
    }
    if (!semaphore_.wait()) {
        return false;
    }
    if (cb_) {
        cb_();
    }
    return true;
}

void sync_timer::__handle_timeout() {
    semaphore_.signal();
}

}  // namespace time
}  // namespace pump
