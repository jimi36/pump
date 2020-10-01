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

#ifndef pump_transport_tls_acceptor_h
#define pump_transport_tls_acceptor_h

#include <unordered_map>

#include "pump/transport/base_acceptor.h"
#include "pump/transport/tls_handshaker.h"
#include "pump/transport/flow/flow_tls_acceptor.h"

namespace pump {
namespace transport {

    class tls_acceptor;
    DEFINE_ALL_POINTER_TYPE(tls_acceptor);

    class LIB_PUMP tls_acceptor : public base_acceptor,
                                  public std::enable_shared_from_this<tls_acceptor> {
      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static tls_acceptor_sptr create_instance_with_file(
            const std::string &cert,
            const std::string &key,
            const address &listen_address,
            int64 handshake_timeout = 0) {
            INLINE_OBJECT_CREATE(
                obj, tls_acceptor, (true, cert, key, listen_address, handshake_timeout));
            return tls_acceptor_sptr(obj, object_delete<tls_acceptor>);
        }

        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static tls_acceptor_sptr create_instance_with_memory(
            const std::string &cert,
            const std::string &key,
            const address &listen_address,
            int64 handshake_timeout = 0) {
            INLINE_OBJECT_CREATE(
                obj, tls_acceptor, (false, cert, key, listen_address, handshake_timeout));
            return tls_acceptor_sptr(obj, object_delete<tls_acceptor>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tls_acceptor();

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual transport_error start(service_ptr sv,
                                      const acceptor_callbacks &cbs) override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_read_event(void_ptr iocp_task) override;
#else
        virtual void on_read_event() override;
#endif

      protected:
        /*********************************************************************************
         * TLS handshaked callback
         ********************************************************************************/
        static void on_handshaked(tls_acceptor_wptr wptr,
                                  tls_handshaker_ptr handshaker,
                                  bool succ);

        /*********************************************************************************
         * Tls handskake stopped callback
         ********************************************************************************/
        static void on_handshake_stopped(tls_acceptor_wptr wptr,
                                         tls_handshaker_ptr handshaker);

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tls_acceptor(bool use_file,
                     const std::string &cert_mem,
                     const std::string &key_mem,
                     const address &listen_address,
                     int64 handshake_timeout);

        /*********************************************************************************
         * Open accept flow
         ********************************************************************************/
        virtual bool __open_accept_flow() override;

        /*********************************************************************************
         * Close accept flow
         ********************************************************************************/
        virtual void __close_accept_flow() override;

        /*********************************************************************************
         * Create handshaker
         ********************************************************************************/
        tls_handshaker_ptr __create_handshaker();

        /*********************************************************************************
         * Remove handshaker
         ********************************************************************************/
        void __remove_handshaker(tls_handshaker_ptr handshaker);

        /*********************************************************************************
         * Stop all handshakers
         ********************************************************************************/
        void __stop_all_handshakers();

      private:
        // GNUTLS credentials
        void_ptr xcred_;

        // GNUTLS handshake timeout time
        int64 handshake_timeout_;

        // Handshakers
        std::mutex handshaker_mx_;
        std::unordered_map<tls_handshaker_ptr, tls_handshaker_sptr> handshakers_;

        // Acceptor flow
        flow::flow_tls_acceptor_sptr flow_;
    };
}  // namespace transport
}  // namespace pump

#endif