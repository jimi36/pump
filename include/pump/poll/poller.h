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

#ifndef pump_poll_poller_h
#define pump_poll_poller_h

#include <map>
#include <thread>

#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/net/socket.h"
#include "pump/poll/channel.h"
#include "pump/toolkit/fl_mc_queue.h"

namespace pump {
namespace poll {

class pump_lib poller : public toolkit::noncopyable {
  protected:
    struct channel_event {
        channel_event(
            std::shared_ptr<channel> &c,
            int32_t ev,
            void *a) noexcept
          : ch(c),
            event(ev),
            arg(a) {}
        channel_wptr ch;
        int32_t event;
        void *arg;
    };

    struct tracker_event {
        tracker_event(
            channel_tracker_sptr &t,
            int32_t ev) noexcept
          : tracker(t),
            event(ev) {}
        channel_tracker_sptr tracker;
        int32_t event;
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    poller() noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~poller() = default;

    /*********************************************************************************
     * Start
     ********************************************************************************/
    virtual bool start();

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    virtual void stop();

    /*********************************************************************************
     * Wait stopped
     ********************************************************************************/
    virtual void wait_stopped();

    /*********************************************************************************
     * Install channel tracker
     ********************************************************************************/
    bool install_channel_tracker(channel_tracker_sptr &tracker);

    /*********************************************************************************
     * Uninstall channel tracker
     ********************************************************************************/
    void uninstall_channel_tracker(channel_tracker_sptr &tracker);

    /*********************************************************************************
     * start channel tracker
     ********************************************************************************/
    bool start_channel_tracker(channel_tracker_sptr &tracker);

    /*********************************************************************************
     * Push channel event
     ********************************************************************************/
    bool push_channel_event(
        channel_sptr &c,
        int32_t event,
        void *arg);

  protected:
    /*********************************************************************************
     * Install channel tracker for derived class
     ********************************************************************************/
    virtual bool __install_channel_tracker(channel_tracker *tracker) {
        return false;
    }

    /*********************************************************************************
     * Uninstall append channel for derived class
     ********************************************************************************/
    virtual bool __uninstall_channel_tracker(channel_tracker *tracker) {
        return false;
    }

    /*********************************************************************************
     * Start channel tracker for derived class
     ********************************************************************************/
    virtual bool __start_channel_tracker(channel_tracker *tracker) {
        return false;
    }

    /*********************************************************************************
     * Poll
     * Timeout is polling timeout time. If set to -1, then no wait
     ********************************************************************************/
    virtual void __poll(int32_t timeout) {}

  private:
    /*********************************************************************************
     * Handle channel events
     ********************************************************************************/
    void __handle_channel_events();

    /*********************************************************************************
     * Handle channel tracker events
     ********************************************************************************/
    void __handle_channel_tracker_events();

  protected:
    // Started status
    std::atomic_bool started_;

    // Worker thread
    std::shared_ptr<std::thread> worker_;

    // Channel event
    std::atomic_int32_t cev_cnt_;
    toolkit::fl_mc_queue<channel_event *> cevents_;

    // Channel tracker event
    std::atomic_int32_t tev_cnt_;
    toolkit::fl_mc_queue<tracker_event *> tevents_;

    // Channel trackers
    std::map<channel_tracker *, channel_tracker_sptr> trackers_;
};
DEFINE_SMART_POINTERS(poller);

}  // namespace poll
}  // namespace pump

#endif
