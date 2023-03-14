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

#ifndef pump_time_engine_h
#define pump_time_engine_h

#include <map>
#include <list>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

#include <pump/time/timer.h>
#include <pump/toolkit/freelock_queue.h>
#include <pump/toolkit/freelock_m2m_queue.h>

namespace pump {
namespace time {

class engine;
DEFINE_SMART_POINTERS(engine);

typedef std::list<timer_wptr> timer_list;
DEFINE_SMART_POINTERS(timer_list);

class pump_lib engine : public toolkit::noncopyable {
  protected:
    typedef pump_function<void(timer_list_sptr &)> timer_pending_callback;

  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static engine_sptr create() {
        pump_object_create_inline(engine, obj);
        return engine_sptr(obj, pump_object_destroy<engine>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~engine() = default;

    /*********************************************************************************
     * Start
     ********************************************************************************/
    bool start(const timer_pending_callback &cb);

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    pump_inline void stop() {
        started_.store(false);
    }

    /*********************************************************************************
     * Wait stopping
     ********************************************************************************/
    void wait_stopped();

    /*********************************************************************************
     * Start timer
     ********************************************************************************/
    bool start_timer(timer_sptr &ptr);

    /*********************************************************************************
     * Restart timer
     * Just user code must don't call this function.
     ********************************************************************************/
    bool restart_timer(timer_sptr &&ptr);

  protected:
    /*********************************************************************************
     * Observe thread
     ********************************************************************************/
    void __observe_thread();

    /*********************************************************************************
     * Observe timers
     ********************************************************************************/
    void __observe(
        timer_list_sptr &tl,
        uint64_t &next_time_ns,
        uint64_t now_ns);

    /*********************************************************************************
     * Observe timers
     ********************************************************************************/
    pump_inline void __queue_timer(timer_sptr &ptr, uint64_t now_ns) {
        timers_[ptr->timeout() + now_ns].push_back(ptr);
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    engine() noexcept;

  private:
    // Started status
    std::atomic_bool started_;

    // Observer thread
    std::shared_ptr<std::thread> observer_;

    // New timers
    typedef toolkit::freelock_m2m_queue<timer_sptr> timer_impl_queue;
    toolkit::freelock_queue<timer_impl_queue> new_timers_;

    // Observed Timers
    std::map<uint64_t, timer_list> timers_;

    // Timeout callback
    timer_pending_callback pending_cb_;
};

}  // namespace time
}  // namespace pump

#endif
