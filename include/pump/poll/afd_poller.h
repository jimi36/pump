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

#ifndef pump_poll_afd_poller_h
#define pump_poll_afd_poller_h

#include "pump/poll/poller.h"

namespace pump {
namespace poll {

    class afd_poller
        : public poller {

      public:
        /*********************************************************************************
          * Constructor
         ********************************************************************************/
        afd_poller() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~afd_poller();

      protected:
        /*********************************************************************************
         * Install channel tracker for derived class
         ********************************************************************************/
        virtual bool __install_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Uninstall append channel for derived class
         ********************************************************************************/
        virtual bool __uninstall_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Resume channel tracker for derived class
         ********************************************************************************/
        virtual bool __resume_channel_tracker(channel_tracker_ptr tracker) override;

        /*********************************************************************************
         * Poll
         ********************************************************************************/
        virtual void __poll(int32_t timeout) override;

      private:
        /*********************************************************************************
         * Dispatch pending event
         ********************************************************************************/
        void __dispatch_pending_event(int32_t count);

      private:
        // IOCP handler
        void_ptr iocp_handler_;
        // AFD device handler
        void_ptr afd_device_handler_;

        void_ptr events_;
        int32_t max_event_count_;
        std::atomic_int32_t cur_event_count_;
    };

}
}

#endif