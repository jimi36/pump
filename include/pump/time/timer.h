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
    void stop();

    /*********************************************************************************
     * Handle timeout
     ********************************************************************************/
    void handle_timeout();

    /*********************************************************************************
     * Get timeout 
     ********************************************************************************/
    pump_inline uint64_t timeout() const {
        return timeout_ns_;
    }

    /*********************************************************************************
     * Get starting state
     ********************************************************************************/
    bool is_started() const;

    /*********************************************************************************
     * Get repeated status
     ********************************************************************************/
    pump_inline bool is_repeated() const {
        return repeated_;
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    timer(uint64_t timeout_ns, const timer_callback &cb, bool repeated);

    /*********************************************************************************
     * Start
     ********************************************************************************/
    bool __start(manager *mgr);

    /*********************************************************************************
     * Set state
     ********************************************************************************/
    pump_inline bool __set_state(int32_t expected, int32_t desired) {
        return state_.compare_exchange_strong(expected, desired);
    }

    /*********************************************************************************
     * Set state
     ********************************************************************************/
    pump_inline void __force_set_state(int32_t desired) {
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
