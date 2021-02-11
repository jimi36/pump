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

#ifndef pump_timer_queue_h
#define pump_timer_queue_h

#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>

#include "pump/debug.h"
#include "pump/time/timer.h"
#include "pump/toolkit/freelock_multi_queue.h"
#include "pump/toolkit/freelock_single_queue.h"
#include "pump/toolkit/freelock_block_queue.h"

namespace pump {
namespace time {

    class timer_queue
      : public toolkit::noncopyable {

      protected:
        typedef pump_function<void(timer_wptr&&)> timer_pending_callback;

      public:
          /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static timer_queue_sptr create() {
            INLINE_OBJECT_CREATE(obj, timer_queue, ());
            return timer_queue_sptr(obj, object_delete<timer_queue>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~timer_queue();

        /*********************************************************************************
         * Start
         ********************************************************************************/
        bool start(const timer_pending_callback &cb);

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        PUMP_INLINE void stop() {
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
         ********************************************************************************/
        void __observe(uint64_t now);

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        timer_queue() noexcept;

      private:
        // Started status
        std::atomic_bool started_;

        // Next observer time
        uint64_t next_observe_time_;

        // Observer thread
        std::shared_ptr<std::thread> observer_;

        // New timers
        typedef toolkit::freelock_multi_queue<timer_sptr> timer_impl_queue;
        toolkit::freelock_block_queue<timer_impl_queue> new_timers_;

        // Observed Timers
        std::multimap<uint64_t, timer_wptr> timers_;

        // Timeout callback
        timer_pending_callback pending_cb_;

    };
    DEFINE_ALL_POINTER_TYPE(timer_queue);

}  // namespace time
}  // namespace pump

#endif
