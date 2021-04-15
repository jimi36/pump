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
#include "pump/toolkit/freelock_multi_queue.h"
#include "pump/toolkit/freelock_single_queue.h"
#include "pump/toolkit/freelock_block_queue.h"

namespace pump {

    const int32_t READ_POLLER = 0;
    const int32_t SEND_POLLER = 1;

    class LIB_PUMP service 
      : public toolkit::noncopyable {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        service(bool enable_poller = true);

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

        /*********************************************************************************
         * Add channel checker
         ********************************************************************************/
        bool add_channel_tracker(
            poll::channel_tracker_sptr &tracker, 
            int32_t pi);

        /*********************************************************************************
         * Delete channel
         ********************************************************************************/
        void remove_channel_tracker(
            poll::channel_tracker_sptr &tracker, 
            int32_t pi);

        /*********************************************************************************
         * Resume channel
         ********************************************************************************/
        bool resume_channel_tracker(
            poll::channel_tracker_ptr tracker, 
            int32_t pi);

        /*********************************************************************************
         * Post channel event
         ********************************************************************************/
        bool post_channel_event(
            poll::channel_sptr &ch, 
            int32_t event);

        /*********************************************************************************
         * Post callback task
         ********************************************************************************/
        template <typename PostedTaskType>
        PUMP_INLINE void post(PostedTaskType &&task) {
            posted_tasks_.enqueue(std::forward<PostedTaskType>(task));
        }

        /*********************************************************************************
         * Start timer
         ********************************************************************************/
        bool start_timer(time::timer_sptr &timer);

      private:
        /*********************************************************************************
        * Post pending timer
        ********************************************************************************/
        PUMP_INLINE void __post_pending_timer(time::timer_wptr &&timer) {
            pending_timers_.enqueue(std::move(timer));
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

        // Pollers
        poll::poller_ptr pollers_[2];

        // Posted task worker
        std::shared_ptr<std::thread> posted_task_worker_;
        typedef pump_function<void()> posted_task_type;
        typedef toolkit::freelock_multi_queue<posted_task_type> task_impl_queue;
        toolkit::freelock_block_queue<task_impl_queue> posted_tasks_;

        // Timer queue
        time::timer_queue_sptr timers_;

        // Timeout timer worker
        std::shared_ptr<std::thread> pending_timer_worker_;
        typedef toolkit::freelock_single_queue<time::timer_wptr> timer_impl_queue;
        toolkit::freelock_block_queue<timer_impl_queue> pending_timers_;
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
