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

#ifndef pump_service_h
#define pump_service_h

#include "pump/poll/poller.h"
#include "pump/time/timer_queue.h"
#include "pump/toolkit/multi_freelock_queue.h"
#include "pump/toolkit/single_freelock_queue.h"
#include "pump/toolkit/block_freelock_queue.h"

namespace pump {

#define READ_POLLER 0
#define WRITE_POLLER 1

    class LIB_PUMP service 
      : public toolkit::noncopyable {

      protected:
        typedef pump_function<void()> post_task_type;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        service(bool with_poller = true);

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~service();

        /*********************************************************************************
         * Start
         ********************************************************************************/
        bool start();

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        void stop();

        /*********************************************************************************
         * Wait stopping
         ********************************************************************************/
        void wait_stopped();

#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Add channel checker
         ********************************************************************************/
        bool add_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pt);

        /*********************************************************************************
         * Delete channel
         ********************************************************************************/
        void remove_channel_tracker(poll::channel_tracker_sptr &tracker, int32_t pt);

        /*********************************************************************************
         * Resume channel
         ********************************************************************************/
        bool resume_channel_tracker(poll::channel_tracker_ptr tracker, int32_t pt);
#endif
        /*********************************************************************************
         * Post channel event
         ********************************************************************************/
        bool post_channel_event(poll::channel_sptr &ch, int32_t event);

        /*********************************************************************************
         * Post callback task
         ********************************************************************************/
        PUMP_INLINE void post(const post_task_type &task) {
            posted_tasks_.enqueue(task);
        }

        /*********************************************************************************
         * Start timer
         ********************************************************************************/
        bool start_timer(time::timer_sptr &tr);

      private:
        /*********************************************************************************
        * Post timeout timer
        ********************************************************************************/
        PUMP_INLINE void __post_timeout_timer(time::timer_wptr &timer) {
            timeout_timers_.enqueue(timer);
        }

        /*********************************************************************************
         * Start posted task worker
         ********************************************************************************/
        void __start_posted_task_worker();

        /*********************************************************************************
         * Start timeout timer worker
         ********************************************************************************/
        void __start_timeout_timer_worker();

      private:
        // Running status
        bool running_;

        // Read poller
        poll::poller_ptr read_poller_;
        // Write poller
        poll::poller_ptr send_poller_;
        // IOCP poller
        poll::poller_ptr iocp_poller_;

        // Timer queue
        time::timer_queue_sptr tqueue_;

        // Posted task worker
        std::shared_ptr<std::thread> posted_task_worker_;
        typedef toolkit::multi_freelock_queue<post_task_type> task_impl_queue;
        toolkit::block_freelock_queue<task_impl_queue> posted_tasks_;

        // Timout timer worker
        std::shared_ptr<std::thread> timeout_timer_worker_;
        typedef toolkit::single_freelock_queue<time::timer_wptr> timer_impl_queue;
        toolkit::block_freelock_queue<timer_impl_queue> timeout_timers_;
    };
    DEFINE_ALL_POINTER_TYPE(service);

    class LIB_PUMP service_getter {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        service_getter(service_ptr sv) noexcept
          : service_(sv) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~service_getter() = default;

        /*********************************************************************************
         * Get service
         ********************************************************************************/
        PUMP_INLINE service_ptr get_service() {
            return service_;
        }

      protected:
        /*********************************************************************************
         * Set service
         ********************************************************************************/
        PUMP_INLINE void __set_service(service_ptr sv) {
            service_ = sv;
        }

      private:
        service_ptr service_;
    };

}  // namespace pump

#endif
