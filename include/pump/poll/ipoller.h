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

#ifndef pump_poll_ipoller_h
#define pump_poll_ipoller_h

#include <vector>

#include "pump/net/iocp.h"
#include "pump/poll/poller.h"

namespace pump {
namespace poll {

    class iocp_poller
      : public poller {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        iocp_poller() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~iocp_poller();

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual bool start() override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

        /*********************************************************************************
         * Wait stopping
         ********************************************************************************/
        virtual void wait_stopped() override;

        /*********************************************************************************
         * Push channel event
         ********************************************************************************/
        virtual void push_channel_event(channel_sptr &c, uint32 ev) override;

      protected:
        /*********************************************************************************
         * Work thread
         ********************************************************************************/
        void __work_thread();

      private:
        // IOCP handler
        void_ptr iocp_;
        // IOCP worker threads
        std::vector<std::thread *> workrs_;
    };

    DEFINE_ALL_POINTER_TYPE(iocp_poller);

}  // namespace poll
}  // namespace pump

#endif