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

#ifndef pump_time_timer_h
#define pump_time_timer_h

#include <atomic>

#include "pump/types.h"

namespace pump {
namespace time {

const static int32_t state_none = 0;
const static int32_t state_stopped = 1;
const static int32_t state_started = 2;
const static int32_t state_pending = 3;

class manager;

class timer;
DEFINE_SMART_POINTERS(timer);

typedef pump_function<void()> timer_callback;

class pump_lib timer : public std::enable_shared_from_this<timer> {
  protected:
    friend class manager;

  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static timer_sptr create(
        uint64_t timeout_ns,
        const timer_callback &cb,
        bool repeated = false) {
        INLINE_OBJECT_CREATE(obj, timer, (timeout_ns, cb, repeated));
        return timer_sptr(obj, object_delete<timer>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~timer() = default;

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    pump_inline void stop() pump_noexcept {
        __force_set_state(state_stopped);
    }

    /*********************************************************************************
     * Handle timeout
     ********************************************************************************/
    void handle_timeout();

    /*********************************************************************************
     * Get timeout
     ********************************************************************************/
    pump_inline uint64_t timeout() const pump_noexcept {
        return timeout_ns_;
    }

    /*********************************************************************************
     * Get starting state
     ********************************************************************************/
    pump_inline bool is_started() const pump_noexcept {
        return state_.load() > state_stopped;
    }

    /*********************************************************************************
     * Get repeated status
     ********************************************************************************/
    pump_inline bool is_repeated() const pump_noexcept {
        return repeated_;
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    timer(
        uint64_t timeout_ns,
        const timer_callback &cb,
        bool repeated) pump_noexcept;

    /*********************************************************************************
     * Start
     ********************************************************************************/
    pump_inline bool __start(manager *mgr) pump_noexcept {
        if (!__set_state(state_none, state_started)) {
            return false;
        }
        mgr_ = mgr;
        return true;
    }

    /*********************************************************************************
     * Set state
     ********************************************************************************/
    pump_inline bool __set_state(
        int32_t expected,
        int32_t desired) pump_noexcept {
        return state_.compare_exchange_strong(expected, desired);
    }

    /*********************************************************************************
     * Set state
     ********************************************************************************/
    pump_inline void __force_set_state(int32_t desired) pump_noexcept {
        state_.store(desired);
    }

  private:
    // Timer manager
    manager *mgr_;
    // Timer state
    std::atomic_int32_t state_;
    // Timer callback
    timer_callback cb_;
    // Repeated flag
    bool repeated_;
    // Timeout time
    uint64_t timeout_ns_;
};

}  // namespace time
}  // namespace pump

#endif
