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

#ifndef pump_time_manager_h
#define pump_time_manager_h

#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>

#include "pump/time/timer.h"
#include "pump/toolkit/fl_queue.h"
#include "pump/toolkit/fl_mc_queue.h"

namespace pump {
namespace time {

class manager;
DEFINE_SMART_POINTER_TYPE(manager);

class pump_lib manager : public toolkit::noncopyable {
  protected:
    typedef pump_function<void(timer_list_sptr &)> timer_pending_callback;

  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static manager_sptr create() {
        INLINE_OBJECT_CREATE(obj, manager, ());
        return manager_sptr(obj, object_delete<manager>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~manager();

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
     * Just timer can call this function, user code must dont call this.
     ********************************************************************************/
    bool restart_timer(timer_sptr &&ptr);

  protected:
    /*********************************************************************************
     * Observe thread
     ********************************************************************************/
    void __observe_thread();

    /*********************************************************************************
     * Observe timers
     * If there are more timers in queue, it will update next observe time.
     ********************************************************************************/
    void __observe(timer_list_sptr &tl,
                   uint64_t &next_observe_time,
                   uint64_t now);

    /*********************************************************************************
     * Observe timers
     ********************************************************************************/
    pump_inline void __queue_timer(timer_list_sptr &tl,
                                   timer_sptr &&ptr,
                                   uint64_t now) {
        if (ptr->time() <= now) {
            tl->push_back(std::move(ptr));
        } else {
            timers_[ptr->time()].push_back(std::move(ptr));
        }
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    manager() noexcept;

  private:
    // Started status
    std::atomic_bool started_;

    // Observer thread
    std::shared_ptr<std::thread> observer_;

    // New timers
    typedef toolkit::fl_mc_queue<timer_sptr> timer_impl_queue;
    toolkit::fl_queue<timer_impl_queue> new_timers_;

    // Observed Timers
    std::map<uint64_t, timer_list> timers_;

    // Timeout callback
    timer_pending_callback pending_cb_;
};

}  // namespace time
}  // namespace pump

#endif
