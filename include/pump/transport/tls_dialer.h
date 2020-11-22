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

#ifndef pump_transport_tls_dialer_h
#define pump_transport_tls_dialer_h

#include <future>

#include "pump/transport/base_dialer.h"
#include "pump/transport/tls_handshaker.h"
#include "pump/transport/flow/flow_tls_dialer.h"

namespace pump {
namespace transport {

    class tls_dialer;
    DEFINE_ALL_POINTER_TYPE(tls_dialer);

    class LIB_PUMP tls_dialer
      : public base_dialer,
        public std::enable_shared_from_this<tls_dialer> {

      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static tls_dialer_sptr create(const address &local_address,
                                                  const address &remote_address,
                                                  int64 dial_timeout = 0,
                                                  int64 handshake_timeout = 0) {
            INLINE_OBJECT_CREATE(
                obj,
                tls_dialer,
                (local_address, remote_address, dial_timeout, handshake_timeout));
            return tls_dialer_sptr(obj, object_delete<tls_dialer>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tls_dialer() = default;

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual transport_error start(service_ptr sv,
                                      const dialer_callbacks &cbs) override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

      protected:
        /*********************************************************************************
         * Send event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_send_event(net::iocp_task_ptr iocp_task) override;
#else
        virtual void on_send_event() override;
#endif
      protected:
        /*********************************************************************************
         * Timeout event callback
         ********************************************************************************/
        static void on_timeout(tls_dialer_wptr wptr);

        /*********************************************************************************
         * TLS handshake success callback
         ********************************************************************************/
        static void on_handshaked(tls_dialer_wptr wptr,
                                  tls_handshaker_ptr handshaker,
                                  bool succ);

        /*********************************************************************************
         * Tls handskake stopped callback
         ********************************************************************************/
        static void on_handshake_stopped(tls_dialer_wptr wptr,
                                         tls_handshaker_ptr handshaker);

      protected:
        /*********************************************************************************
         * Open dial flow
         ********************************************************************************/
        virtual bool __open_dial_flow() override;

        /*********************************************************************************
         * Close dial flow
         ********************************************************************************/
        virtual void __close_dial_flow() override {
            if (flow_)
                flow_->close();
        }

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tls_dialer(const address &local_address,
                   const address &remote_address,
                   int64 dial_timeout,
                   int64 handshake_timeout) noexcept;

      private:
        // GNUTLS credentials
        void_ptr xcred_;

        // Handshake timeout
        int64 handshake_timeout_;
        // Handshaker
        tls_handshaker_sptr handshaker_;

        // Dialer flow
        flow::flow_tls_dialer_sptr flow_;
    };

    class tls_sync_dialer;
    DEFINE_ALL_POINTER_TYPE(tls_sync_dialer);

    class LIB_PUMP tls_sync_dialer
      : public std::enable_shared_from_this<tls_sync_dialer> {

      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        static tls_sync_dialer_sptr create() {
            INLINE_OBJECT_CREATE(obj, tls_sync_dialer, ());
            return tls_sync_dialer_sptr(obj, object_delete<tls_sync_dialer>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tls_sync_dialer() = default;

        /*********************************************************************************
         * Dial by sync
         ********************************************************************************/
        base_transport_sptr dial(service_ptr sv,
                                 const address &local_address,
                                 const address &remote_address,
                                 int64 connect_timeout,
                                 int64 handshake_timeout);

      protected:
        /*********************************************************************************
         * Dialed callback
         ********************************************************************************/
        static void on_dialed(tls_sync_dialer_wptr wptr,
                              base_transport_sptr &transp,
                              bool succ);

        /*********************************************************************************
         * Dial timeouted callback
         ********************************************************************************/
        static void on_timeouted(tls_sync_dialer_wptr wptr);

        /*********************************************************************************
         * Dial stopped callback
         ********************************************************************************/
        static void on_stopped();

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tls_sync_dialer() noexcept {
        }

        /*********************************************************************************
         * Reset sync dialer
         ********************************************************************************/
        PUMP_INLINE void __reset() {
            dialer_.reset();
        }

      private:
        // Tcp dialer
        tls_dialer_sptr dialer_;
        // Dial promise
        std::promise<base_transport_sptr> dial_promise_;
    };

}  // namespace transport
}  // namespace pump

#endif