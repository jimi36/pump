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

#ifndef pump_transport_tls_handshaker_h
#define pump_transport_tls_handshaker_h

#include "pump/time/timer.h"
#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

    class tls_handshaker;
    DEFINE_ALL_POINTER_TYPE(tls_handshaker);

    class tls_handshaker : public base_channel,
                           public std::enable_shared_from_this<tls_handshaker> {
      public:
        struct tls_handshaker_callbacks {
            pump_function<void(tls_handshaker_ptr, bool)> handshaked_cb;
            pump_function<void(tls_handshaker_ptr)> stopped_cb;
        };

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tls_handshaker() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tls_handshaker() {
#if !defined(PUMP_HAVE_IOCP)
            __stop_handshake_tracker();
#endif
        }

        /*********************************************************************************
         * Init
         ********************************************************************************/
        void init(int32 fd,
                  bool client,
                  void_ptr xcred,
                  const address &local_address,
                  const address &remote_address);

        /*********************************************************************************
         * Start tls handshaker
         ********************************************************************************/
        bool start(service_ptr sv, int64 timeout, const tls_handshaker_callbacks &cbs);

        /*********************************************************************************
         * Stop transport
         ********************************************************************************/
        void stop();

        /*********************************************************************************
         * Unlock flow
         ********************************************************************************/
        PUMP_INLINE flow::flow_tls_sptr unlock_flow() {
            return std::move(flow_);
        }

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
         * Read event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_read_event(net::iocp_task_ptr iocp_task) override;
#else
        virtual void on_read_event() override;
#endif

        /*********************************************************************************
         * Send event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_send_event(net::iocp_task_ptr iocp_task) override;
#else
        virtual void on_send_event() override;
#endif

        /*********************************************************************************
         * Timer timeout callback
         ********************************************************************************/
        static void on_timeout(tls_handshaker_wptr wptr);

      private:
        /*********************************************************************************
         * Open flow
         ********************************************************************************/
        bool __open_flow(int32 fd, void_ptr xcred, bool client);

        /*********************************************************************************
         * Close flow
         ********************************************************************************/
        PUMP_INLINE void __close_flow() {
            if (flow_) {
                flow_->close();
            }
        }

        /*********************************************************************************
         * Process handshake
         ********************************************************************************/
        void __process_handshake(flow::flow_tls_ptr flow);

        /*********************************************************************************
         * Start handshake timer
         ********************************************************************************/
        bool __start_handshake_timer(int64 timeout);

        /*********************************************************************************
         * Stop handshake timer
         ********************************************************************************/
        void __stop_handshake_timer();

#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Start handshake tracker
         ********************************************************************************/
        void __start_handshake_tracker();

        /*********************************************************************************
         * Stop handshake tracker
         ********************************************************************************/
        void __stop_handshake_tracker();
#endif
        /*********************************************************************************
         * Handshake finished
         ********************************************************************************/
        void __handshake_finished();

      private:
        // Local address
        address local_address_;
        // Remote address
        address remote_address_;

        // Finished flag
        std::atomic_flag flag_;

        // Handshake timeout timer
        time::timer_sptr timer_;

#if !defined(PUMP_HAVE_IOCP)
        // Channel tracker
        poll::channel_tracker_sptr tracker_;
#endif
        // TLS flow
        flow::flow_tls_sptr flow_;

        // TLS handshaker callbacks
        tls_handshaker_callbacks cbs_;
    };

}  // namespace transport
}  // namespace pump

#endif