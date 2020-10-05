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
#include "pump/toolkit/freelock.h"

namespace pump {
namespace poll {

    class poller : public toolkit::noncopyable {
      protected:
        struct channel_event {
            channel_event(std::shared_ptr<channel> &c, uint32 ev) noexcept
                : ch(c), event(ev) {
            }
            channel_wptr ch;
            uint32 event;
        };
        DEFINE_RAW_POINTER_TYPE(channel_event);

        struct channel_tracker_event {
            channel_tracker_event(channel_tracker_sptr &t, int32 ev) noexcept
                : tracker(t), event(ev) {
            }
            channel_tracker_sptr tracker;
            int32 event;
        };
        DEFINE_RAW_POINTER_TYPE(channel_tracker_event);

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
        virtual void stop() {
            started_.store(false);
        }

        /*********************************************************************************
         * Wait stopped
         ********************************************************************************/
        virtual void wait_stopped();

#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Add channel tracker
         ********************************************************************************/
        virtual bool add_channel_tracker(channel_tracker_sptr &tracker);

        /*********************************************************************************
         * Remove channel tracker
         ********************************************************************************/
        virtual void remove_channel_tracker(channel_tracker_sptr &tracker);

        /*********************************************************************************
         * Awake channel tracker
         ********************************************************************************/
        virtual void resume_channel_tracker(channel_tracker_ptr tracker);
#endif

        /*********************************************************************************
         * Push channel event
         ********************************************************************************/
        virtual void push_channel_event(channel_sptr &c, uint32 event);

      protected:
        /*********************************************************************************
         * Add channel tracker for derived class
         ********************************************************************************/
        virtual bool __add_channel_tracker(channel_tracker_ptr tracker) {
            return true;
        }

        /*********************************************************************************
         * Remove append channel for derived class
         ********************************************************************************/
        virtual bool __remove_channel_tracker(channel_tracker_ptr tracker) {
            return true;
        }


        /*********************************************************************************
         * Awake channel tracker for derived class
         ********************************************************************************/
        virtual void __resume_channel_tracker(channel_tracker_ptr tracker) {
        }

        /*********************************************************************************
         * Poll
         * Timeout is polling timeout time. If set to -1, then no wait
         ********************************************************************************/
        virtual void __poll(int32 timeout) {
        }

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
        toolkit::freelock_list_queue<channel_event_ptr> cevents_;

        // Channel tracker event
        std::atomic_int32_t tev_cnt_;
        toolkit::freelock_list_queue<channel_tracker_event_ptr> tevents_;

        // Channel trackers
        std::map<channel_tracker_ptr, channel_tracker_sptr> trackers_;
    };

    DEFINE_ALL_POINTER_TYPE(poller);

}  // namespace poll
}  // namespace pump

#endif
