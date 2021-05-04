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

#ifndef pump_transport_tcp_acceptor_h
#define pump_transport_tcp_acceptor_h

#include "pump/transport/base_acceptor.h"
#include "pump/transport/flow/flow_tcp_acceptor.h"

namespace pump {
namespace transport {

    class tcp_acceptor;
    DEFINE_ALL_POINTER_TYPE(tcp_acceptor);

    class LIB_PUMP tcp_acceptor
      : public base_acceptor,
        public std::enable_shared_from_this<tcp_acceptor> {

      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static tcp_acceptor_sptr create(const address &listen_address) {
            INLINE_OBJECT_CREATE(obj, tcp_acceptor, (listen_address));
            return tcp_acceptor_sptr(obj, object_delete<tcp_acceptor>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tcp_acceptor() = default;

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual error_code start(
            service *sv, 
            const acceptor_callbacks &cbs) override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
        virtual void on_read_event() override;

      private:
        /*********************************************************************************
         * Open accept flow
         ********************************************************************************/
        virtual bool __open_accept_flow() override;

        /*********************************************************************************
         * Close accept flow
         ********************************************************************************/
        virtual void __close_accept_flow() override;

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tcp_acceptor(const address &listen_address) noexcept;

      private:
        // Acceptor flow
        flow::flow_tcp_acceptor_sptr flow_;
    };

}  // namespace transport
}  // namespace pump

#endif
