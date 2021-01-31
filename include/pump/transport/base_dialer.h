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

#ifndef pump_transport_dialer_h
#define pump_transport_dialer_h

#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

    class LIB_PUMP base_dialer
      : public base_channel {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_dialer(int32_t type,
                    const address &local_address,
                    const address &remote_address,
                    int64_t connect_timeout) noexcept
          : base_channel(type, nullptr, -1),
            local_address_(local_address),
            remote_address_(remote_address),
            connect_timeout_(connect_timeout) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_dialer() {
            __stop_dial_tracker();
        }

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual int32_t start(service_ptr sv, const dialer_callbacks &cbs) = 0;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() = 0;

        /*********************************************************************************
         * Get local address
         ********************************************************************************/
        PUMP_INLINE const address &get_local_address() const {
            return local_address_;
        }

        /*********************************************************************************
         * Get remote address
         ********************************************************************************/
        PUMP_INLINE const address &get_remote_address() const {
            return remote_address_;
        }

      protected:
        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(int32_t ev) override;

      protected:
        /*********************************************************************************
         * Open dial flow
         ********************************************************************************/
          virtual bool __open_dial_flow() = 0;

        /*********************************************************************************
         * Close dial flow
         ********************************************************************************/
        virtual void __close_dial_flow() {
        }

      protected:
        /*********************************************************************************
         * Start dial tracker
         ********************************************************************************/
        bool __start_dial_tracker(poll::channel_sptr &&ch);

        /*********************************************************************************
         * Stop dial tracker
         ********************************************************************************/
        void __stop_dial_tracker();

        /*********************************************************************************
         * Start dial timer
         ********************************************************************************/
        bool __start_dial_timer(const time::timer_callback &cb);

        /*********************************************************************************
         * Stop connect timer
         ********************************************************************************/
        void __stop_dial_timer();

        /*********************************************************************************
         * Trigger interrupt callbacks
         ********************************************************************************/
        void __trigger_interrupt_callbacks();

      protected:
        // Local address
        address local_address_;
        // Remote address
        address remote_address_;

        // Connect timer
        int64_t connect_timeout_;
        std::shared_ptr<time::timer> connect_timer_;

        // Channel tracker
        poll::channel_tracker_sptr tracker_;

        // Dialer callbacks
        dialer_callbacks cbs_;
    };
    DEFINE_ALL_POINTER_TYPE(base_dialer);

}  // namespace transport
}  // namespace pump

#endif