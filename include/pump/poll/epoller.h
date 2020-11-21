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

#ifndef pump_poll_epoller_h
#define pump_poll_epoller_h

#include "pump/poll/poller.h"

namespace pump {
namespace poll {

    class epoll_poller
      : public poller {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        epoll_poller() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~epoll_poller();

      protected:
        /*********************************************************************************
         * Add channel tracker for derived class
         ********************************************************************************/
        virtual bool __add_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Remove append channel for derived class
         ********************************************************************************/
        virtual bool __remove_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Awake channel tracker for derived class
         ********************************************************************************/
        virtual void __resume_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Poll
         ********************************************************************************/
        virtual void __poll(int32 timeout) override;

      private:
        /*********************************************************************************
         * Dispatch pending event
         ********************************************************************************/
        void __dispatch_pending_event(int32 count);

      private:
        int32 fd_;
        void_ptr events_;
    };

    DEFINE_ALL_POINTER_TYPE(epoll_poller);

}  // namespace poll
}  // namespace pump

#endif
