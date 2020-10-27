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

#ifndef pump_transport_acceptor_h
#define pump_transport_acceptor_h

#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

    class LIB_PUMP base_acceptor : public base_channel {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_acceptor(transport_type type, const address &listen_address) noexcept
            : base_channel(type, nullptr, -1), 
              listen_address_(listen_address) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_acceptor();

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual transport_error start(service_ptr sv, const acceptor_callbacks &cbs) = 0;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() = 0;

        /*********************************************************************************
         * Get local address
         ********************************************************************************/
        PUMP_INLINE const address &get_listen_address() const {
            return listen_address_;
        }

    protected:
        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(uint32 ev) override;

      protected:
        /*********************************************************************************
         * Open accept flow
         ********************************************************************************/
        virtual bool __open_accept_flow() = 0;

        /*********************************************************************************
         * Close accept flow
         ********************************************************************************/
        virtual void __close_accept_flow() {
        }

      protected:
#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Start accept tracker
         ********************************************************************************/
        bool __start_accept_tracker(poll::channel_sptr &&ch);

        /*********************************************************************************
         * Stop accept tracker
         ********************************************************************************/
        void __stop_accept_tracker();
#endif
        /*********************************************************************************
         * Trigger interrupt callbacks
         ********************************************************************************/
        void __trigger_interrupt_callbacks();

      protected:
        // Listen address
        address listen_address_;

#if !defined(PUMP_HAVE_IOCP)
        // Channel tracker
        poll::channel_tracker_sptr tracker_;
#endif
        // Acceptor callbacks
        acceptor_callbacks cbs_;
    };
    DEFINE_ALL_POINTER_TYPE(base_acceptor);

}  // namespace transport
}  // namespace pump

#endif