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

#ifndef pump_transport_udp_transport_h
#define pump_transport_udp_transport_h

#include "pump/transport/flow/flow_udp.h"
#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

    class udp_transport;
    DEFINE_ALL_POINTER_TYPE(udp_transport);

    class LIB_PUMP udp_transport : public base_transport,
                                   public std::enable_shared_from_this<udp_transport> {
      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static udp_transport_sptr create_instance(
            const address &local_address) {
            INLINE_OBJECT_CREATE(obj, udp_transport, (local_address));
            return udp_transport_sptr(obj, object_delete<udp_transport>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~udp_transport() = default;

        /*********************************************************************************
         * Start
         * max_pending_send_size is ignore on udp transport.
         ********************************************************************************/
        virtual transport_error start(service_ptr sv,
                                      int32 max_pending_send_size,
                                      const transport_callbacks &cbs) override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

        /*********************************************************************************
         * Force stop
         ********************************************************************************/
        virtual void force_stop() override {
            stop();
        }

        /*********************************************************************************
         * Read for once
         ********************************************************************************/
        virtual transport_error read_for_once();

        /*********************************************************************************
         * Read for loop
         ********************************************************************************/
        virtual transport_error read_for_loop();

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual transport_error send(c_block_ptr b,
                                     uint32 size,
                                     const address &address) override;

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_read_event(void_ptr iocp_task) override;
#else
        virtual void on_read_event() override;
#endif

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        udp_transport(const address &local_address) noexcept;

        /*********************************************************************************
         * Open transport flow
         ********************************************************************************/
        bool __open_transport_flow();

        /*********************************************************************************
         * Shutdown transport flow
         ********************************************************************************/
        PUMP_INLINE void __shutdown_transport_flow() {
            if (flow_) {
                flow_->shutdown();
            }
        }

        /*********************************************************************************
         * Close transport flow
         ********************************************************************************/
        virtual void __close_transport_flow() override {
            if (flow_) {
                flow_->close();
            }
        }

        /*********************************************************************************
         * Async read
         ********************************************************************************/
        transport_error __async_read(uint32 state);

      private:
        // Udp flow
        flow::flow_udp_sptr flow_;
    };

}  // namespace transport
}  // namespace pump

#endif
