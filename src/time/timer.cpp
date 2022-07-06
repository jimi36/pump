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
#include "pump/time/manager.h"
#include "pump/time/timestamp.h"

namespace pump {
namespace time {

constexpr static int32_t state_none = 0;
constexpr static int32_t state_stopped = 1;
constexpr static int32_t state_started = 2;
constexpr static int32_t state_pending = 3;

timer::timer(
    uint64_t timeout,
    const timer_callback &cb,
    bool repeated) :
    mgr_(nullptr),
    state_(state_none),
    cb_(cb),
    repeated_(repeated),
    timeout_ns_(timeout) {
}

void timer::stop() {
    __force_set_state(state_stopped);
}

void timer::handle_timeout() {
    if (__set_state(state_started, state_pending)) {
        cb_();

        if (pump_likely(repeated_)) {
            if (__set_state(state_pending, state_started)) {
                // Add to timer manager.
                mgr_->restart_timer(shared_from_this());
            }
        } else {
            __set_state(state_pending, state_stopped);
        }
    }
}

bool timer::is_started() const {
    return state_.load() > state_stopped;
}

bool timer::__start(manager *mgr) {
    if (!__set_state(state_none, state_started)) {
        return false;
    }

    // Save timer manager.
    mgr_ = mgr;

    return true;
}

}  // namespace time
}  // namespace pump
