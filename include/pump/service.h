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
#include "pump/time/manager.h"
#include "pump/toolkit/fl_queue.h"
#include "pump/toolkit/fl_mc_queue.h"
#include "pump/toolkit/fl_sc_queue.h"

namespace pump {

/*********************************************************************************
 * Poller id in service
 ********************************************************************************/
typedef int32_t poller_id;
const poller_id read_pid = 0;
const poller_id send_pid = 1;

class pump_lib service : public toolkit::noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    service(bool enable_poll = true);

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
     * Get poller
     ********************************************************************************/
    pump_inline poll::poller *get_poller(poller_id pid) {
        pump_assert(pid <= send_pid);
        return pollers_[pid];
    }

    /*********************************************************************************
     * Post channel event
     ********************************************************************************/
    pump_inline bool post_channel_event(
        poll::channel_sptr &ch,
        int32_t event,
        void *arg,
        poller_id pid) {
        pump_assert(pid <= send_pid);
        if (pump_likely(!!pollers_[pid])) {
            return pollers_[pid]->push_channel_event(ch, event, arg);
        }
        return false;
    }

    /*********************************************************************************
     * Post task callback
     ********************************************************************************/
    template <typename TaskCallbackType>
    pump_inline void post(TaskCallbackType &&task) {
        posted_tasks_.enqueue(std::forward<TaskCallbackType>(task));
    }

    /*********************************************************************************
     * Start timer
     ********************************************************************************/
    pump_inline bool start_timer(time::timer_sptr &timer) {
        auto queue = timers_;
        if (pump_likely(!!queue)) {
            return queue->start_timer(timer);
        }
        return false;
    }

  private:
    /*********************************************************************************
     * Post triggered timers
     ********************************************************************************/
    void __post_triggered_timers(time::timer_list_sptr &tl);

    /*********************************************************************************
     * Start task worker
     ********************************************************************************/
    void __start_task_worker();

    /*********************************************************************************
     * Start timer callback worker
     ********************************************************************************/
    void __start_timer_callback_worker();

  private:
    // Status
    bool running_;

    // Pollers
    poll::poller *pollers_[2];

    // Task worker
    std::shared_ptr<std::thread> task_worker_;
    typedef pump_function<void()> task_callback;
    typedef toolkit::fl_mc_queue<task_callback> task_queue;
    toolkit::fl_queue<task_queue> posted_tasks_;

    // Timers
    time::manager_sptr timers_;

    // Timer worker
    std::shared_ptr<std::thread> timer_worker_;
    typedef toolkit::fl_sc_queue<time::timer_list_sptr> timer_queue;
    toolkit::fl_queue<timer_queue> triggered_timers_;
};
DEFINE_SMART_POINTERS(service);

class pump_lib service_getter {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    service_getter(service *sv) pump_noexcept
      : service_(sv) {}

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~service_getter() = default;

    /*********************************************************************************
     * Get service
     ********************************************************************************/
    pump_inline service *get_service() pump_noexcept {
        return service_;
    }

  protected:
    /*********************************************************************************
     * Set service
     ********************************************************************************/
    pump_inline void __set_service(service *sv) pump_noexcept {
        service_ = sv;
    }

  private:
    service *service_;
};

}  // namespace pump

#endif
