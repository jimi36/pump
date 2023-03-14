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

#include <pump/toolkit/semaphore.h>

namespace pump {
namespace time {

typedef int32_t timer_state_type;
const static timer_state_type timer_state_none = 0;
const static timer_state_type timer_state_stopped = 1;
const static timer_state_type timer_state_started = 2;
const static timer_state_type timer_state_pending = 3;

class engine;

class timer;
DEFINE_SMART_POINTERS(timer);

typedef pump_function<void()> timer_callback;

class pump_lib timer : public std::enable_shared_from_this<timer> {
  protected:
    friend class engine;

  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static timer_sptr create(
        bool repeated,
        uint64_t timeout_ns,
        const timer_callback &cb) {
        pump_object_create_inline(timer, obj, repeated, timeout_ns, cb);
        return timer_sptr(obj, pump_object_destroy<timer>);
    }

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    void stop() noexcept;

    /*********************************************************************************
     * Handle timeout
     * User code must not call this.
     ********************************************************************************/
    void handle_timeout();

    /*********************************************************************************
     * Get timeout
     ********************************************************************************/
    pump_inline uint64_t timeout() const noexcept {
        return timeout_ns_;
    }

    /*********************************************************************************
     * Get starting state
     ********************************************************************************/
    pump_inline bool is_started() const noexcept {
        return state_.load() > timer_state_stopped;
    }

    /*********************************************************************************
     * Get repeated status
     ********************************************************************************/
    pump_inline bool is_repeated() const noexcept {
        return repeated_;
    }

  protected:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    timer(
        bool repeated,
        uint64_t timeout_ns,
        const timer_callback &cb) noexcept;

    /*********************************************************************************
     * Disable copy constructor
     ********************************************************************************/
    timer(const timer &) = delete;

    /*********************************************************************************
     * Disable assign operator
     ********************************************************************************/
    timer operator=(const timer &) = delete;

    /*********************************************************************************
     * Start
     ********************************************************************************/
    bool __start(engine *e) noexcept;

    /*********************************************************************************
     * Set state
     ********************************************************************************/
    bool __set_state(int32_t expected, int32_t desired) noexcept;

  private:
    // Timer engine
    engine *e_;

    // Timer state
    std::atomic_int32_t state_;

    // Repeated flag
    bool repeated_;
    // Timeout time
    uint64_t timeout_ns_;
    // Timer callback
    timer_callback cb_;
};

class pump_lib sync_timer {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    sync_timer(
        uint64_t timeout_ns,
        const timer_callback &cb);

    /*********************************************************************************
     * Start
     * This function will be blocked until timeout and callback finished.
     ********************************************************************************/
    bool start(engine *e);

  private:
    /*********************************************************************************
     * Disable copy constructor
     ********************************************************************************/
    sync_timer(const sync_timer &) = delete;

    /*********************************************************************************
     * Disable assign operator
     ********************************************************************************/
    sync_timer operator=(const sync_timer &) = delete;

     /*********************************************************************************
     * Handle timeout
     ********************************************************************************/
    void __handle_timeout();

  private:
    // Timer
    timer_sptr raw_;

    // Timer callback
    timer_callback cb_;

    toolkit::semaphore semaphore_;
};

}  // namespace time
}  // namespace pump

#endif
